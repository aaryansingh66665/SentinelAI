import os
import time
import json
from typing import List, Dict, Any, Callable

# Try importing google.generativeai
try:
    import google.generativeai as genai
    HAS_GENAI = True
except ImportError:
    HAS_GENAI = False

class Agent:
    """
    Represents an autonomous AI Agent with a specific role, instructions, and tools.
    """
    def __init__(
        self,
        name: str,
        role: str,
        system_instruction: str,
        model_name: str = "gemini-1.5-flash",
        api_key: str = None,
        tools: List[Callable] = None
    ):
        self.name = name
        self.role = role
        self.system_instruction = system_instruction
        self.model_name = model_name
        self.api_key = api_key or os.environ.get("GEMINI_API_KEY")
        self.tools = tools or []
        self.client = None
        
        self._initialize_client()

    def _initialize_client(self):
        if HAS_GENAI and self.api_key:
            try:
                genai.configure(api_key=self.api_key)
                self.client = genai.GenerativeModel(
                    model_name=self.model_name,
                    system_instruction=self.system_instruction
                )
            except Exception as e:
                print(f"[{self.name}] Error configuring Gemini client: {e}. Falling back to simulation mode.")
                self.client = None

    def run(self, prompt: str, context: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Executes the agent logic, using Gemini if configured, otherwise falling back to tool execution/simulation.
        """
        context = context or {}
        print(f"[{self.name}] Executing task: {prompt[:80]}...")
        
        # Emulate thinking delay
        time.sleep(1.0)

        # If LLM client is available, run prompt through LLM
        if self.client:
            try:
                # Include tools descriptions or schemas if necessary
                # We also provide contextual data as JSON string in the prompt
                context_str = json.dumps(context, indent=2)
                full_prompt = f"Context Data:\n{context_str}\n\nTask Instruction:\n{prompt}"
                
                response = self.client.generate_content(full_prompt)
                text = response.text.strip()
                
                # Check if JSON is expected (heuristically checking if prompt asks for JSON)
                if "json" in prompt.lower():
                    # Clean markdown code blocks
                    if text.startswith("```json"):
                        text = text[7:]
                    if text.endswith("```"):
                        text = text[:-3]
                    text = text.strip()
                    try:
                        return {
                            "status": "success",
                            "agent": self.name,
                            "log": f"Task completed successfully by LLM.",
                            "data": json.loads(text)
                        }
                    except json.JSONDecodeError:
                        # Return raw text if JSON parsing fails
                        return {
                            "status": "success",
                            "agent": self.name,
                            "log": f"LLM returned text (failed to parse JSON).",
                            "data": text
                        }
                
                return {
                    "status": "success",
                    "agent": self.name,
                    "log": f"Task completed successfully by LLM.",
                    "data": text
                }
            except Exception as e:
                print(f"[{self.name}] Gemini generation failed: {e}. Falling back to rule-based tools.")
        
        # Fallback tool or simulation logic
        # If the agent has matching tools, execute them
        for tool in self.tools:
            try:
                # Heuristic: try to call tool with context or prompt
                # If tool takes specific kwargs, we can try to inspect or use try/except
                res = tool(prompt, context)
                return {
                    "status": "success",
                    "agent": self.name,
                    "log": f"Completed via tool '{tool.__name__}'.",
                    "data": res
                }
            except TypeError:
                try:
                    res = tool(context)
                    return {
                        "status": "success",
                        "agent": self.name,
                        "log": f"Completed via tool '{tool.__name__}'.",
                        "data": res
                    }
                except Exception as tool_err:
                    print(f"[{self.name}] Error running tool {tool.__name__}: {tool_err}")

        # Default fallback response if no tools worked
        return {
            "status": "success",
            "agent": self.name,
            "log": "Completed via default simulation behavior (no active LLM or matching tool).",
            "data": f"Simulated output for: {prompt}"
        }


class Task:
    """
    Defines an instruction to be processed by a specific Agent, with designated context mapping.
    """
    def __init__(
        self,
        name: str,
        agent: Agent,
        instruction: str,
        input_key: str = None,
        output_key: str = None
    ):
        self.name = name
        self.agent = agent
        self.instruction = instruction
        self.input_key = input_key
        self.output_key = output_key

    def execute(self, context: Dict[str, Any]) -> Any:
        # Prepare input context
        input_data = context.get(self.input_key) if self.input_key else context
        
        # Generate target prompt incorporating dynamic instructions
        prompt = self.instruction
        if self.input_key:
            prompt = f"Perform '{self.instruction}' using the input data stored in '{self.input_key}'."
            
        result = self.agent.run(prompt, context=input_data)
        
        # Store result back into workflow context
        if self.output_key:
            context[self.output_key] = result
            
        return result


class Workflow:
    """
    A Graph/Sequential Multi-Agent Orchestrator executing tasks.
    """
    def __init__(self, name: str):
        self.name = name
        self.tasks: List[Task] = []

    def add_task(self, task: Task):
        self.tasks.append(task)
        return self

    def run(self, initial_context: Dict[str, Any] = None) -> Dict[str, Any]:
        context = initial_context or {}
        print(f"[Workflow: {self.name}] Starting workflow execution...")
        
        results = {}
        for task in self.tasks:
            print(f"[Workflow: {self.name}] Running task: {task.name}")
            res = task.execute(context)
            results[task.output_key or task.name] = res
            
        print(f"[Workflow: {self.name}] Workflow execution completed.")
        return {
            "workflow_name": self.name,
            "status": "success",
            "results": results,
            "context": context
        }
