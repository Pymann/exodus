import argparse
import io
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from PIL import Image

from exodus.tools.image.image import ImageTool


class ImageToolTests(unittest.TestCase):
    def test_parse_rgb_accepts_hex_color_code(self) -> None:
        self.assertEqual(ImageTool.parse_rgb("#f93b90"), (249, 59, 144))
        self.assertEqual(ImageTool.parse_rgb("f93b90"), (249, 59, 144))

    def test_default_output_dir_appends_tiles_suffix(self) -> None:
        self.assertEqual(
            ImageTool.default_output_dir(Path("icons/map.png")),
            Path("icons/map_tiles"),
        )

    def test_resolve_output_dir_uses_subdirectories_for_multi_input(
        self,
    ) -> None:
        self.assertEqual(
            ImageTool.resolve_output_dir(
                input_png=Path("icons/map.png"),
                requested_output_dir="out/tiles",
                multi_input=True,
            ),
            Path("out/tiles/map"),
        )

    def test_resolve_output_path_uses_directory_for_multi_input(self) -> None:
        self.assertEqual(
            ImageTool.resolve_output_path(
                input_png=Path("icons/map.png"),
                requested_output="out/rendered",
                multi_input=True,
                default_name="map_128.png",
            ),
            Path("out/rendered/map_128.png"),
        )

    def test_save_tiles_skips_partial_edges_without_padding(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            input_png = root / "sheet.png"
            output_dir = root / "tiles"
            Image.new("RGBA", (300, 128), (255, 0, 255, 255)).save(input_png)

            saved, skipped = ImageTool.save_tiles(
                input_png=input_png,
                output_dir=output_dir,
                tile_size=128,
                pad_edge=False,
            )

            self.assertEqual((saved, skipped), (2, 1))
            self.assertEqual(
                sorted(path.name for path in output_dir.glob("*.png")),
                ["sheet_r00_c00.png", "sheet_r00_c01.png"],
            )

    def test_save_tiles_pads_partial_edges_when_requested(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            input_png = root / "sheet.png"
            output_dir = root / "tiles"
            Image.new("RGBA", (300, 128), (255, 0, 255, 255)).save(input_png)

            saved, skipped = ImageTool.save_tiles(
                input_png=input_png,
                output_dir=output_dir,
                tile_size=128,
                pad_edge=True,
            )

            self.assertEqual((saved, skipped), (3, 0))
            with Image.open(output_dir / "sheet_r00_c02.png") as tile:
                self.assertEqual(tile.size, (128, 128))

    def test_run_slice_accepts_multiple_input_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            first = root / "first.png"
            second = root / "second.png"
            output_dir = root / "tiles"
            Image.new("RGBA", (128, 128), (255, 0, 255, 255)).save(first)
            Image.new("RGBA", (128, 128), (0, 255, 255, 255)).save(second)
            args = argparse.Namespace(
                action="slice",
                input_png=[str(first), str(second)],
                output_dir=str(output_dir),
                tile_size=128,
                pad_edge=False,
            )

            self.assertEqual(ImageTool(args).run(), 0)
            self.assertTrue(
                (output_dir / "first" / "first_r00_c00.png").exists()
            )
            self.assertTrue(
                (output_dir / "second" / "second_r00_c00.png").exists()
            )

    def test_run_slice_returns_error_for_non_positive_tile_size(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            input_png = root / "sheet.png"
            Image.new("RGBA", (128, 128), (255, 0, 255, 255)).save(input_png)
            args = argparse.Namespace(
                action="slice",
                input_png=[str(input_png)],
                output_dir=None,
                tile_size=0,
                pad_edge=False,
            )

            self.assertEqual(ImageTool(args).run(), 1)

    def test_run_scale_contains_writes_default_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            input_png = root / "portrait.png"
            Image.new("RGBA", (256, 64), (10, 20, 30, 255)).save(input_png)
            args = argparse.Namespace(
                action="scale",
                input_png=[str(input_png)],
                output=None,
                mode="contain",
                resample="nearest",
                background="transparent",
            )

            self.assertEqual(ImageTool(args).run(), 0)
            output = root / "portrait_128.png"
            self.assertTrue(output.exists())
            with Image.open(output) as image:
                self.assertEqual(image.size, (128, 128))

    def test_run_scale_uses_output_directory_for_multi_input(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            first = root / "first.png"
            second = root / "second.png"
            output_dir = root / "scaled"
            Image.new("RGBA", (128, 64), (255, 0, 0, 255)).save(first)
            Image.new("RGBA", (64, 128), (0, 255, 0, 255)).save(second)
            args = argparse.Namespace(
                action="scale",
                input_png=[str(first), str(second)],
                output=str(output_dir),
                mode="cover",
                resample="lanczos",
                background="transparent",
            )

            self.assertEqual(ImageTool(args).run(), 0)
            self.assertTrue((output_dir / "first_128.png").exists())
            self.assertTrue((output_dir / "second_128.png").exists())

    def test_to_snake_case_name_normalizes_mixed_text(self) -> None:
        self.assertEqual(
            ImageTool.to_snake_case_name("Card Editor"), "card_editor"
        )
        self.assertEqual(
            ImageTool.to_snake_case_name("Boss-Fight++"), "boss_fight"
        )

    def test_run_snake_case_renames_globbed_inputs_in_place(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            first = root / "Card Editor.PNG"
            second = root / "Trade Button!!.png"
            Image.new("RGBA", (1, 1), (0, 0, 0, 255)).save(first)
            Image.new("RGBA", (1, 1), (0, 0, 0, 255)).save(second)
            args = argparse.Namespace(
                action="snake-case",
                input_png=[str(root / "*.png"), str(root / "*.PNG")],
            )

            self.assertEqual(ImageTool(args).run(), 0)
            self.assertTrue((root / "card_editor.png").exists())
            self.assertTrue((root / "trade_button.png").exists())
            self.assertFalse(first.exists())
            self.assertFalse(second.exists())

    def test_run_border_color_reports_hex_for_globbed_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            first = root / "first.png"
            second = root / "second.png"
            Image.new("RGBA", (4, 4), (249, 59, 144, 255)).save(first)
            Image.new("RGBA", (4, 4), (248, 66, 155, 255)).save(second)
            args = argparse.Namespace(
                action="border-color",
                input_png=[str(root / "*.png")],
            )

            stdout = io.StringIO()
            with redirect_stdout(stdout):
                self.assertEqual(ImageTool(args).run(), 0)

            lines = stdout.getvalue().strip().splitlines()
            self.assertEqual(len(lines), 2)
            self.assertIn(f"{first}: rgb=249,59,144 hex=#f93b90", lines)
            self.assertIn(f"{second}: rgb=248,66,155 hex=#f8429b", lines)

    def test_run_snake_case_rejects_existing_target(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            source = root / "Card Editor.png"
            target = root / "card_editor.png"
            Image.new("RGBA", (1, 1), (0, 0, 0, 255)).save(source)
            Image.new("RGBA", (1, 1), (0, 0, 0, 255)).save(target)
            args = argparse.Namespace(
                action="snake-case",
                input_png=[str(source)],
            )

            self.assertEqual(ImageTool(args).run(), 1)
            self.assertTrue(source.exists())
            self.assertTrue(target.exists())

    def test_run_pink_to_alpha_makes_keyed_pixels_transparent(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            input_png = root / "sprite.png"
            image = Image.new("RGBA", (2, 1), (255, 0, 255, 255))
            image.putpixel((1, 0), (0, 0, 255, 255))
            image.save(input_png)
            args = argparse.Namespace(
                action="pink-to-alpha",
                input_png=[str(input_png)],
                output=None,
                color="255,0,255",
                tolerance=0,
                soft_edge=0,
            )

            self.assertEqual(ImageTool(args).run(), 0)
            output = root / "sprite.png"
            self.assertTrue(output.exists())
            with Image.open(output) as result:
                self.assertEqual(result.getpixel((0, 0))[3], 0)
                self.assertEqual(result.getpixel((1, 0))[3], 255)

    def test_run_pink_to_alpha_expands_glob_patterns(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            first = root / "first.png"
            second = root / "second.png"
            output_dir = root / "transparent"
            Image.new("RGBA", (1, 1), (255, 0, 255, 255)).save(first)
            Image.new("RGBA", (1, 1), (255, 0, 255, 255)).save(second)
            args = argparse.Namespace(
                action="pink-to-alpha",
                input_png=[str(root / "*.png")],
                output=str(output_dir),
                color="255,0,255",
                tolerance=0,
                soft_edge=0,
            )

            self.assertEqual(ImageTool(args).run(), 0)
            self.assertTrue((output_dir / "first.png").exists())
            self.assertTrue((output_dir / "second.png").exists())

    def test_run_pink_to_alpha_uses_output_directory_for_multi_input(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            first = root / "first.png"
            second = root / "second.png"
            output_dir = root / "transparent"
            Image.new("RGBA", (1, 1), (255, 0, 255, 255)).save(first)
            Image.new("RGBA", (1, 1), (255, 0, 255, 255)).save(second)
            args = argparse.Namespace(
                action="pink-to-alpha",
                input_png=[str(first), str(second)],
                output=str(output_dir),
                color="255,0,255",
                tolerance=0,
                soft_edge=0,
            )

            self.assertEqual(ImageTool(args).run(), 0)
            self.assertTrue((output_dir / "first.png").exists())
            self.assertTrue((output_dir / "second.png").exists())


if __name__ == "__main__":
    unittest.main()
