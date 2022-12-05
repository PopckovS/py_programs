import copy
import json
import argparse
import logging
from pathlib import Path

SOURCE_DIR = 'source'
OUTPUT_DIR = 'output'
SOURCE_TEMPL = 'template.json'
SOURCE_STATUS = 'status.json'
NOT_VALID_STATUS = ['canceled']


def generate_task(task_id: str, name: str) -> None:
    """
    Генерирует json файлы по шаблону из json.
    """
    source_dir = Path(SOURCE_DIR)

    # получаем json шаблон для заполнения
    tmpl_path = source_dir / SOURCE_TEMPL
    templ = json.load(open(tmpl_path))

    # получаем json файл для парсинга
    source_path = source_dir / task_id / SOURCE_STATUS
    sources = json.load(open(source_path))
    processing = sources['chapter_1']
    tasks = sources['chapter_2']

    # получаем имя для
    processing_name = processing['field_1']
    processing_type = processing['field_2']
    cloud_filters = processing['field_3']
    area_of_interests = Path(name) / Path(processing['field_4']).name

    # валидируем json по статусу
    valid_tasks = []
    for task in tasks:
        if task['files'] and task['status'] not in NOT_VALID_STATUS:
            valid_tasks.append(task)

    # генерируем json
    output_tasks = []
    for files in valid_tasks:
        new_task = copy.copy(templ)
        new_task['id'] = str(files['processing_id']) + ':' + str(files['uuid'])
        new_task['field_1'] = str(files['files']['new_image'])
        new_task['field_4'] = str(area_of_interests)
        new_task['field_2'] = processing_type
        new_task['field_3'] = processing_name
        output_tasks.append(new_task)

    # сохраняем результат
    path_to_save = Path(OUTPUT_DIR) / task_id / 'output.json'
    path_to_save.parent.mkdir(parents=True, exist_ok=True)
    with open(path_to_save, 'w', encoding='UTF-8') as out_file:
        json.dump(output_tasks, out_file, indent=2, ensure_ascii=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--run',
                        required=False,
                        help='Запуск генерации json файлов',
                        type=argparse.FileType(mode='r', encoding='utf-8'))
    args = parser.parse_args()
    if args.run:
        data = args.run.read()
        task = json.loads(data)
        task_id = task.get('task_id')
        name = task.get('name')
        generate_task(task_id, name)
