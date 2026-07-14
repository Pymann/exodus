"""Image processing helpers for the Exodus CLI."""

from __future__ import annotations

import argparse
import glob
import re
from pathlib import Path
from typing import Iterable

from PIL import Image

from exodus.core.logger import get_logger


class ImageTool:
    """Perform simple image processing tasks for asset workflows."""

    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.logger = get_logger(__name__)

    @staticmethod
    def ensure_png(path: Path) -> None:
        if not path.exists():
            raise FileNotFoundError(f"Input file does not exist: {path}")
        if path.suffix.lower() != ".png":
            raise ValueError(f"Input file must be a PNG: {path}")

    @staticmethod
    def default_output_dir(input_png: Path) -> Path:
        return input_png.with_name(f"{input_png.stem}_tiles")

    @staticmethod
    def default_scaled_output_path(input_png: Path) -> Path:
        return input_png.with_name(f"{input_png.stem}_128.png")

    @staticmethod
    def default_alpha_output_path(input_png: Path) -> Path:
        return input_png.with_name(input_png.name)

    @classmethod
    def resolve_output_dir(
        cls,
        input_png: Path,
        requested_output_dir: str | None,
        multi_input: bool,
    ) -> Path:
        if not requested_output_dir:
            return cls.default_output_dir(input_png)

        output_dir = Path(requested_output_dir)
        if multi_input:
            return output_dir / input_png.stem
        return output_dir

    @staticmethod
    def resolve_output_path(
        input_png: Path,
        requested_output: str | None,
        multi_input: bool,
        default_name: str,
    ) -> Path:
        if not requested_output:
            return input_png.with_name(default_name)

        output_path = Path(requested_output)
        if multi_input:
            output_path.mkdir(parents=True, exist_ok=True)
            return output_path / default_name
        return output_path

    @staticmethod
    def save_tiles(
        input_png: Path, output_dir: Path, tile_size: int, pad_edge: bool
    ) -> tuple[int, int]:
        output_dir.mkdir(parents=True, exist_ok=True)

        with Image.open(input_png) as image:
            image = image.convert("RGBA")
            width, height = image.size

            saved = 0
            skipped = 0

            for top in range(0, height, tile_size):
                for left in range(0, width, tile_size):
                    right = min(left + tile_size, width)
                    bottom = min(top + tile_size, height)

                    crop = image.crop((left, top, right, bottom))
                    crop_width, crop_height = crop.size

                    if crop_width != tile_size or crop_height != tile_size:
                        if not pad_edge:
                            skipped += 1
                            continue

                        padded = Image.new(
                            "RGBA", (tile_size, tile_size), (0, 0, 0, 0)
                        )
                        padded.paste(crop, (0, 0))
                        crop = padded

                    col = left // tile_size
                    row = top // tile_size
                    tile_name = f"{input_png.stem}_r{row:02d}_c{col:02d}.png"
                    crop.save(output_dir / tile_name)
                    saved += 1

        return saved, skipped

    @staticmethod
    def parse_rgba(value: str) -> tuple[int, int, int, int]:
        if value == "transparent":
            return (0, 0, 0, 0)

        parts = value.split(",")
        if len(parts) != 4:
            raise ValueError(
                "--background must be 'transparent' or four comma-separated"
                " RGBA values"
            )

        values = [int(part) for part in parts]
        if any(channel < 0 or channel > 255 for channel in values):
            raise ValueError(
                "RGBA background values must be between 0 and 255"
            )
        return (values[0], values[1], values[2], values[3])

    @staticmethod
    def parse_rgb(value: str) -> tuple[int, int, int]:
        hex_value = value.strip().lstrip("#")
        if len(hex_value) == 6 and all(
            ch in "0123456789abcdefABCDEF" for ch in hex_value
        ):
            return (
                int(hex_value[0:2], 16),
                int(hex_value[2:4], 16),
                int(hex_value[4:6], 16),
            )

        parts = value.split(",")
        if len(parts) != 3:
            raise ValueError(
                "--color must be R,G,B or a 6-digit hex value like #ff00ff"
            )
        values = [int(part) for part in parts]
        if any(channel < 0 or channel > 255 for channel in values):
            raise ValueError("RGB values must be between 0 and 255")
        return (values[0], values[1], values[2])

    @staticmethod
    def get_resample(name: str) -> int:
        mapping = {
            "nearest": Image.Resampling.NEAREST,
            "bilinear": Image.Resampling.BILINEAR,
            "bicubic": Image.Resampling.BICUBIC,
            "lanczos": Image.Resampling.LANCZOS,
        }
        return int(mapping[name])

    @staticmethod
    def scale_stretch(image: Image.Image, resample: int) -> Image.Image:
        return image.resize((128, 128), resample=resample)

    @staticmethod
    def scale_contain(
        image: Image.Image,
        resample: int,
        background: tuple[int, int, int, int],
    ) -> Image.Image:
        src_w, src_h = image.size
        scale = min(128 / src_w, 128 / src_h)
        new_w = max(1, round(src_w * scale))
        new_h = max(1, round(src_h * scale))

        resized = image.resize((new_w, new_h), resample=resample)
        canvas = Image.new("RGBA", (128, 128), background)
        offset_x = (128 - new_w) // 2
        offset_y = (128 - new_h) // 2
        canvas.paste(resized, (offset_x, offset_y), resized)
        return canvas

    @staticmethod
    def scale_cover(image: Image.Image, resample: int) -> Image.Image:
        src_w, src_h = image.size
        scale = max(128 / src_w, 128 / src_h)
        new_w = max(1, round(src_w * scale))
        new_h = max(1, round(src_h * scale))

        resized = image.resize((new_w, new_h), resample=resample)
        left = (new_w - 128) // 2
        top = (new_h - 128) // 2
        return resized.crop((left, top, left + 128, top + 128))

    @staticmethod
    def channel_distance(
        pixel: tuple[int, int, int], key: tuple[int, int, int]
    ) -> int:
        return max(
            abs(pixel[0] - key[0]),
            abs(pixel[1] - key[1]),
            abs(pixel[2] - key[2]),
        )

    @staticmethod
    def format_rgb_hex(rgb: tuple[int, int, int]) -> str:
        return f"#{rgb[0]:02x}{rgb[1]:02x}{rgb[2]:02x}"

    @staticmethod
    def sample_border_rgb(image: Image.Image) -> tuple[int, int, int]:
        width, height = image.size
        points = {
            (0, 0),
            (width - 1, 0),
            (0, height - 1),
            (width - 1, height - 1),
            (width // 2, 0),
            (width // 2, height - 1),
            (0, height // 2),
            (width - 1, height // 2),
        }
        samples = [image.getpixel(point)[:3] for point in points]
        return tuple(
            round(sum(sample[channel] for sample in samples) / len(samples))
            for channel in range(3)
        )

    @staticmethod
    def to_snake_case_name(name: str) -> str:
        normalized = re.sub(r"[^0-9A-Za-z]+", "_", name).strip("_").lower()
        return normalized or "unnamed"

    @classmethod
    def snake_case_path(cls, path: Path) -> Path:
        suffix = path.suffix.lower()
        normalized_name = cls.to_snake_case_name(path.stem)
        return path.with_name(f"{normalized_name}{suffix}")

    @staticmethod
    def normalize_inputs(raw_inputs: Iterable[str]) -> list[Path]:
        normalized: list[Path] = []
        seen: set[Path] = set()

        for raw_input in raw_inputs:
            matches = glob.glob(raw_input)
            expanded = matches if matches else [raw_input]

            for candidate in expanded:
                path = Path(candidate)
                if path in seen:
                    continue
                seen.add(path)
                normalized.append(path)

        return normalized

    def _run_slice(self) -> int:
        if self.args.tile_size <= 0:
            raise ValueError("--tile-size must be greater than 0")

        input_pngs = self.normalize_inputs(self.args.input_png)
        multi_input = len(input_pngs) > 1

        for input_png in input_pngs:
            self.ensure_png(input_png)
            output_dir = self.resolve_output_dir(
                input_png=input_png,
                requested_output_dir=self.args.output_dir,
                multi_input=multi_input,
            )
            saved, skipped = self.save_tiles(
                input_png=input_png,
                output_dir=output_dir,
                tile_size=self.args.tile_size,
                pad_edge=self.args.pad_edge,
            )

            self.logger.info(
                "saved %s tile(s) from %s to %s", saved, input_png, output_dir
            )
            if skipped:
                self.logger.info(
                    "skipped %s partial edge tile(s) for %s; use --pad-edge to"
                    " keep them",
                    skipped,
                    input_png,
                )
        return 0

    def _run_scale(self) -> int:
        input_pngs = self.normalize_inputs(self.args.input_png)
        multi_input = len(input_pngs) > 1
        resample = self.get_resample(self.args.resample)
        background = self.parse_rgba(self.args.background)

        for input_png in input_pngs:
            self.ensure_png(input_png)
            output = self.resolve_output_path(
                input_png=input_png,
                requested_output=self.args.output,
                multi_input=multi_input,
                default_name=self.default_scaled_output_path(input_png).name,
            )

            with Image.open(input_png) as image:
                image = image.convert("RGBA")
                if self.args.mode == "stretch":
                    result = self.scale_stretch(image, resample)
                elif self.args.mode == "contain":
                    result = self.scale_contain(image, resample, background)
                else:
                    result = self.scale_cover(image, resample)

                output.parent.mkdir(parents=True, exist_ok=True)
                result.save(output)

            self.logger.info("saved scaled image %s -> %s", input_png, output)
        return 0

    def _run_snake_case(self) -> int:
        input_pngs = self.normalize_inputs(self.args.input_png)

        for input_png in input_pngs:
            self.ensure_png(input_png)
            output = self.snake_case_path(input_png)
            if output == input_png:
                self.logger.info("name already snake_case: %s", input_png)
                continue
            if output.exists():
                raise FileExistsError(
                    f"Refusing to rename {input_png} to existing path {output}"
                )
            input_png.rename(output)
            self.logger.info("renamed %s -> %s", input_png, output)
        return 0

    def _run_border_color(self) -> int:
        input_pngs = self.normalize_inputs(self.args.input_png)

        for input_png in input_pngs:
            self.ensure_png(input_png)

            with Image.open(input_png) as image:
                image = image.convert("RGBA")
                rgb = self.sample_border_rgb(image)

            print(
                f"{input_png}:"
                f" rgb={rgb[0]},{rgb[1]},{rgb[2]} hex={self.format_rgb_hex(rgb)}"
            )
        return 0

    def _run_pink_to_alpha(self) -> int:
        input_pngs = self.normalize_inputs(self.args.input_png)
        multi_input = len(input_pngs) > 1
        key = self.parse_rgb(self.args.color)
        tolerance = max(0, self.args.tolerance)
        soft_edge = max(0, self.args.soft_edge)

        for input_png in input_pngs:
            self.ensure_png(input_png)
            output = self.resolve_output_path(
                input_png=input_png,
                requested_output=self.args.output,
                multi_input=multi_input,
                default_name=self.default_alpha_output_path(input_png).name,
            )

            with Image.open(input_png) as image:
                image = image.convert("RGBA")
                pixels = image.load()
                width, height = image.size

                for y in range(height):
                    for x in range(width):
                        r, g, b, a = pixels[x, y]
                        dist = self.channel_distance((r, g, b), key)

                        if dist <= tolerance:
                            pixels[x, y] = (r, g, b, 0)
                            continue

                        if soft_edge > 0 and dist <= tolerance + soft_edge:
                            factor = (dist - tolerance) / soft_edge
                            new_alpha = round(a * factor)
                            pixels[x, y] = (r, g, b, new_alpha)

                output.parent.mkdir(parents=True, exist_ok=True)
                image.save(output)

            self.logger.info(
                "saved alpha-keyed image %s -> %s", input_png, output
            )
        return 0

    def run(self) -> int:
        try:
            if self.args.action == "slice":
                return self._run_slice()
            if self.args.action == "scale":
                return self._run_scale()
            if self.args.action == "snake-case":
                return self._run_snake_case()
            if self.args.action == "pink-to-alpha":
                return self._run_pink_to_alpha()
            if self.args.action == "border-color":
                return self._run_border_color()
            self.logger.error("Unknown image action: %s", self.args.action)
            return 1
        except Exception as exc:
            self.logger.error("Image tool failed: %s", exc)
            return 1
