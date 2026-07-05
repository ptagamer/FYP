from scripts.merge_dataset import ORIGINAL_CSV, OUTPUT_CSV, SPEAKEASY_CSV, merge_datasets


if __name__ == "__main__":
    merge_datasets(ORIGINAL_CSV, SPEAKEASY_CSV, OUTPUT_CSV)
