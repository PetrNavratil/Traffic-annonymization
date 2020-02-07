class Logger:

    logging_enabled = False

    def __init__(self, logging_enabled):
        self.logging_enabled = logging_enabled

    def __logChanges(self, source, input_value, output_value):
        return f"{source}\t --- \t {input_value}  --> {output_value}"

    def log(self, source, input_value, output_value):
        if self.logging_enabled:
            print(self.__logChanges(source, input_value, output_value))
