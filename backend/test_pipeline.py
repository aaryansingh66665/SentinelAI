import os
import sys

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agents.adk import Agent, Task, Workflow
from tools.security import encrypt_data, decrypt_data, validate_target, validate_ip, validate_ports, TokenBucketRateLimiter
from agents.agents import CyberGuardAgentPipeline

def test_adk_classes():
    print("[TEST] Running ADK core tests...")
    
    # Define simple mock tool
    def mock_tool(prompt, context):
        return {"result": f"mock_value_{context.get('input_param')}"}

    agent = Agent(
        name="TestAgent",
        role="Tester",
        system_instruction="You are a test agent.",
        tools=[mock_tool]
    )
    
    assert agent.name == "TestAgent"
    assert len(agent.tools) == 1
    
    task = Task(
        name="TestTask",
        agent=agent,
        instruction="Run test instruction",
        input_key="input_data",
        output_key="output_data"
    )
    
    context = {"input_data": {"input_param": "hello"}}
    res = task.execute(context)
    
    assert context["output_data"]["status"] == "success"
    assert context["output_data"]["data"]["result"] == "mock_value_hello"
    
    # Workflow test
    workflow = Workflow("TestWorkflow")
    workflow.add_task(task)
    wf_res = workflow.run({"input_data": {"input_param": "workflow"}})
    
    assert wf_res["status"] == "success"
    assert "output_data" in wf_res["results"]
    assert wf_res["context"]["output_data"]["data"]["result"] == "mock_value_workflow"
    print("[PASS] ADK core tests completed successfully.")


def test_security_utilities():
    print("[TEST] Running Security Utilities tests...")
    
    # 1. AES Encryption / Decryption
    secret_text = "sk-geminikey123456789"
    password = "SuperSecretPassword123!"
    
    encrypted = encrypt_data(secret_text, password)
    assert encrypted != secret_text
    
    decrypted = decrypt_data(encrypted, password)
    assert decrypted == secret_text
    
    # Verify decryption failure with bad password
    try:
        decrypt_data(encrypted, "WrongPassword")
        assert False, "Should have raised ValueError for invalid decryption password"
    except ValueError:
        pass # Expected
        
    # 2. Input Validation
    # Targets
    assert validate_target("apex-demo.com") is True
    assert validate_target("sub.domain.co.uk") is True
    assert validate_target("invalid_domain") is False
    assert validate_target("http://google.com") is False # No protocol allowed
    assert validate_target("domain.com/path") is False # No paths
    
    # IPs
    assert validate_ip("192.168.1.1") is True
    assert validate_ip("10.0.0.254") is True
    assert validate_ip("256.0.0.1") is False # Invalid octet
    assert validate_ip("abc.def.ghi.jkl") is False
    
    # Ports
    assert validate_ports([22, 80, 443]) is True
    assert validate_ports([0]) is False # Port 0 is invalid
    assert validate_ports([65536]) is False # Exceeds range
    assert validate_ports(["22"]) is False # Wrong type
    
    # 3. Rate Limiter
    limiter = TokenBucketRateLimiter(rate=1, capacity=2)
    # Check checks
    assert limiter.check_request("127.0.0.1") is True
    assert limiter.check_request("127.0.0.1") is True
    assert limiter.check_request("127.0.0.1") is False # Bucket exhausted
    
    print("[PASS] Security Utilities tests completed successfully.")


def test_scanning_pipeline():
    print("[TEST] Running Scanning Pipeline test...")
    pipeline = CyberGuardAgentPipeline()
    
    # Run scan on pre-configured profile
    recon_res = pipeline.run_recon_agent("ecommerce")
    assert recon_res["status"] == "success"
    assert recon_res["agent"] == "Recon Agent"
    assert "ports" in recon_res["data"]
    
    vuln_res = pipeline.run_vulnerability_agent(recon_res["data"], "ecommerce")
    assert vuln_res["status"] == "success"
    assert len(vuln_res["data"]) > 0
    
    risk_res = pipeline.run_risk_analysis_agent("Apex Footwear", recon_res["data"], vuln_res["data"])
    assert risk_res["status"] == "success"
    assert "risk_level" in risk_res["data"]
    
    report_res = pipeline.run_report_agent("Apex Footwear", "WooCommerce shop", recon_res["data"], risk_res["data"])
    assert report_res["status"] == "success"
    assert "report_markdown" in report_res["data"]
    assert "# " in report_res["data"]["report_markdown"]
    
    print("[PASS] Scanning Pipeline test completed successfully.")


def run_all_tests():
    print("=================== Running CyberGuard AI Test Suite ===================")
    try:
        test_adk_classes()
        test_security_utilities()
        test_scanning_pipeline()
        print("\n[ALL PASS] CyberGuard AI is verified, secure, and ready for deployment.")
        sys.exit(0)
    except AssertionError as ae:
        print(f"\n[FAIL] Test assertion failed: {ae}")
        sys.exit(1)
    except Exception as e:
        print(f"\n[FAIL] Unexpected error during test run: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    run_all_tests()
