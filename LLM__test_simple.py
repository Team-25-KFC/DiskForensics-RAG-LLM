from langflow.custom.custom_component.component import Component
from langflow.io import MessageInput, Output
from langflow.schema.data import Data


class SimpleTestComponent(Component):
    display_name = "Simple Test"
    description = "Simple test component"
    icon = "square-terminal"

    inputs = [
        MessageInput(
            name="input_message",
            display_name="Input Message",
            info="Input message",
            required=True,
        ),
    ]

    outputs = [
        Output(display_name="Output", name="output", type_=Data, method="build"),
    ]

    def build(self):
        # 단순히 입력을 그대로 반환
        raw_data = self.input_message
        
        # 디버깅 로그
        self.log(f"Input type: {type(raw_data)}")
        self.log(f"Input content: {raw_data}")
        
        if hasattr(raw_data, 'text'):
            result_text = raw_data.text
        else:
            result_text = str(raw_data)
            
        self.log(f"Result text: {result_text}")
        
        return Data(data={"text": result_text})
