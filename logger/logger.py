class Logger:

    logging_enabled = False

    def logChanges(self, source, input_value, output_value):
        return f"{source}\t --- \t {input_value}  --> {output_value}"

    def log(self, source, input_value, output_value):
        if self.logging_enabled:
            print(self.logChanges(source, input_value, output_value))
