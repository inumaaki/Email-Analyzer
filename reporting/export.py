import json

def export_to_json(filepath: str, data: dict) -> tuple:
    """
    Exports the analysis results to a JSON file.
    """
    try:
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=4, ensure_ascii=False)
        return True, ""
    except Exception as e:
        return False, str(e)
