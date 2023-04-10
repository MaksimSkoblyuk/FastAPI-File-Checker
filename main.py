import requests
from api_key import API_TOKEN
from binary_search import binary_search

from fastapi import FastAPI
from pydantic import BaseModel, Field, validator
from typing import Tuple, Dict, List, Iterable, Any

# Creating FastAPI app instance.
app: FastAPI = FastAPI(
    title="Suspicious File Checker",
)

# Defining relative paths to suspicious input files.
input_filenames: Tuple[str, ...] = (
    "./local_files/all_queries.txt",
    "./local_files/answers_for_questions_lab2_Linux.txt",
    "./local_files/answers_for_questions_lab2_Parallel_processing_information.docx",
    "./local_files/input_listOfEdgesWeighted.txt",
    "./local_files/integral.mw",
)

# Generating default relative paths of reports over analyzing suspicious files.
report_folder: str = "./reports/"
report_extension: str = ".txt"
report_filenames: Tuple[str, ...] = tuple([report_folder +
                                           input_filename[input_filename.rfind('/') + 1:input_filename.rfind('.')]
                                           + "_report" + report_extension for input_filename in input_filenames])


# Defining File model for generalization information about suspicious files.
# It includes unique id, input filename and report filename for each instance.
# The id is automatically increases after the object is created.
class File(BaseModel):
    id: int = Field(primary_key=True)
    input_filename: str
    report_filename: str

    __last_assigned_id: int = 0

    @validator("id", pre=True, always=True)
    def autoincrement_id(cls, value: int = 1) -> int:
        cls.__last_assigned_id += 1
        return cls.__last_assigned_id

    def __str__(self) -> str:
        return f"{self.id}. File:\n" \
               f"\tinput filename: {self.input_filename};\n" \
               f"\treport filename: {self.report_filename}."


# Creating list of File instances.
FILES: List[File] = [File(id=1, input_filename=input_filename, report_filename=report_filename)
                     for input_filename, report_filename in zip(input_filenames, report_filenames)]

# Defining VirusTotal site url which will be requested with post query
# every time when suspicious file is analyzed.
url: str = "https://www.virustotal.com/api/v3/files"

# Defining dict of headers, which will be transmitted in query.
headers: Dict[str, str] = {
    "accept": "application/json",
    "x-apikey": API_TOKEN,
}


# Post query for the app, checking all suspicious files
# via VirusTotal API and then saving their reports to .txt files.
@app.post("/check/report/")
def check_files(file_ids: List[int]):
    all_ids: List[int] = [file.id for file in FILES]
    answer: Dict[int, Dict[str, Any]] = {}
    for file_id in file_ids:
        index: int = binary_search(sequence=all_ids, value=file_id)
        if index == -1:
            answer[file_id] = {"status": 404, "file": None, "report": None}
            continue

        current_file: File = FILES[index]
        files: Dict[str, Iterable[Any]] = {
            "file": (current_file.input_filename, open(current_file.input_filename, 'rb'), "text/plain")
        }
        response = requests.post(url=url, files=files, headers=headers)
        report_url: str = response.json().get("data", {}).get("links", {}).get("self", "")
        report = requests.get(url=report_url, headers=headers)
        with open(current_file.report_filename, 'w') as file:
            file.write(report.text)
        answer[file_id] = {"status": 200, "file": current_file, "report": report.json()}
    return answer


# Get query for the app, showing all available files
# on the url host/check.
@app.get("/check")
def show_files() -> List[str]:
    response: List[str] = [str(file) for file in FILES]
    return response


# Post query for the app, changing report filename
# for file if it exists. It also adds up common extension .txt
# to new report filename, if it's lack.
@app.post("/check")
def update_report_filename(file_id: int, new_report_filename: str):
    index: int = binary_search(sequence=[file.id for file in FILES], value=file_id)
    if index == -1:
        return
    current_file: File = FILES[index]
    current_file.report_filename = new_report_filename + report_extension \
        if new_report_filename[-4:] != report_extension else new_report_filename
    return {"status": 200, "updated_file": current_file}
