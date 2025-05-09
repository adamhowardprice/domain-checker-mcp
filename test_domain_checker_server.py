import pytest
from unittest.mock import patch, Mock, AsyncMock
import httpx
from domain_checker_server import (
    check_domain_tool,
    check_keyword_tool,
    check_keywords_batch_tool,
    check_single_domain_availability,
    DomainStatus,
)
import asyncio

MOCK_RDAP_REGISTERED = {
    "entities": [
        {
            "roles": ["registrar"],
            "vcardArray": ["vcard", [["fn", {}, "text", "Test Registrar"]]],
        }
    ],
    "events": [
        {"eventAction": "registration", "eventDate": "2023-01-01"},
        {"eventAction": "expiration", "eventDate": "2024-01-01"},
    ],
}


@pytest.mark.asyncio
async def test_check_domain_tool():
    """Test individual domain checking"""
    with (
        patch("aiodns.DNSResolver.query", new_callable=AsyncMock) as mock_dns,
        patch(
            "domain_checker_server.get_rdap_data", new_callable=AsyncMock
        ) as mock_rdap,
        patch(
            "domain_checker_server.client",
            new_callable=lambda: httpx.AsyncClient(),
        ),
    ):
        # Test registered domain first
        mock_dns.return_value = Mock()  # Return a mock object instead of True
        mock_rdap.return_value = (MOCK_RDAP_REGISTERED, 200)

        result = await check_domain_tool("registered.com")

        # Verify mocks were called
        mock_dns.assert_any_call("registered.com", "A")
        mock_rdap.assert_any_call("registered.com")

        # Verify response content
        assert "Status: Registered" in result
        assert "Test Registrar" in result

        # Test available domain
        mock_dns.side_effect = Exception("No DNS")
        mock_rdap.return_value = (None, 404)

        result = await check_domain_tool("available.com")
        assert "Status: Available" in result

        # Test unknown domain (RDAP failure)
        mock_dns.side_effect = Exception("No DNS")
        mock_rdap.return_value = (None, None)

        result = await check_domain_tool("unknown.com")
        assert (
            "Status: Unknown" in result or "could not determine availability" in result
        )


@pytest.mark.asyncio
async def test_check_keyword_tool():
    """Test checking keyword across TLDs"""
    with (
        patch(
            "aiodns.DNSResolver.query",
            new_callable=AsyncMock,
            side_effect=Exception("No DNS"),
        ),
        patch(
            "domain_checker_server.get_rdap_data", new_callable=AsyncMock
        ) as mock_rdap,
        patch(
            "domain_checker_server.client",
            new_callable=lambda: httpx.AsyncClient(),
        ),
    ):
        # All available
        mock_rdap.return_value = (None, 404)
        result = await check_keyword_tool("test", tlds=["com", "net"])
        assert "TLDs checked: 2" in result
        assert "test.com" in result
        assert "test.net" in result
        assert "Unknown status domains: 0" in result

        # All unknown
        mock_rdap.return_value = (None, None)
        result = await check_keyword_tool("test", tlds=["com", "net"])
        assert "Unknown status domains: 2" in result
        assert "test.com" in result
        assert "test.net" in result


@pytest.mark.asyncio
async def test_check_keywords_batch_tool():
    """Test batch processing of keywords"""
    with (
        patch(
            "aiodns.DNSResolver.query",
            new_callable=AsyncMock,
            side_effect=Exception("No DNS"),
        ),
        patch(
            "domain_checker_server.get_rdap_data", new_callable=AsyncMock
        ) as mock_rdap,
        patch(
            "domain_checker_server.client",
            new_callable=lambda: httpx.AsyncClient(),
        ),
    ):
        # All available
        mock_rdap.return_value = (None, 404)
        keywords = ["test1", "test2"]
        tlds = ["com", "net"]
        result = await check_keywords_batch_tool(keywords, tlds)
        assert "Batch Results (2 keywords)" in result
        assert "test1.com" in result
        assert "test2.net" in result
        assert "Unknown status domains: 0" in result

        # All unknown
        mock_rdap.return_value = (None, None)
        result = await check_keywords_batch_tool(keywords, tlds)
        assert (
            "Unknown status domains: 2" in result
            or "Unknown status domains: 4" in result
        )
        assert "test1.com" in result
        assert "test2.net" in result

        # Test empty keywords list
        empty_result = await check_keywords_batch_tool(
            [],
        )
        assert "No keywords provided to check" in empty_result

        # Test list with empty strings
        mock_rdap.return_value = (None, 404)
        partial_result = await check_keywords_batch_tool(["", "test", ""])
        assert "Keyword: test" in partial_result


@pytest.mark.asyncio
async def test_edge_cases():
    """Test edge cases and error handling"""
    with (
        patch(
            "aiodns.DNSResolver.query",
            new_callable=AsyncMock,
            side_effect=Exception("No DNS"),
        ),
        patch(
            "domain_checker_server.get_rdap_data", new_callable=AsyncMock
        ) as mock_rdap,
        patch(
            "domain_checker_server.client",
            new_callable=lambda: httpx.AsyncClient(),
        ),
    ):
        mock_rdap.return_value = (None, 404)

        # Test with invalid characters
        result = await check_domain_tool("test!@#.com")
        assert "Domain:" in result

        # Test with very long domain
        long_result = await check_domain_tool("a" * 100 + ".com")
        assert "Domain:" in long_result

        # Test with None values
        batch_result = await check_keywords_batch_tool([None, "test"])
        assert "Keyword: test" in batch_result


@pytest.mark.asyncio
def test_rdap_logic_registered_200_no_errorcode():
    # 200 status, no errorCode in body => REGISTERED
    with (
        patch("domain_checker_server.check_dns", new_callable=AsyncMock) as mock_dns,
        patch(
            "domain_checker_server.get_rdap_data", new_callable=AsyncMock
        ) as mock_rdap,
    ):
        mock_dns.return_value = False
        mock_rdap.return_value = ({}, 200)
        status, _ = (
            pytest.run(asyncio.run(check_single_domain_availability("registered.com")))
            if hasattr(pytest, "run")
            else asyncio.get_event_loop().run_until_complete(
                check_single_domain_availability("registered.com")
            )
        )
        assert status == DomainStatus.REGISTERED


@pytest.mark.asyncio
def test_rdap_logic_available_404():
    # 404 status => AVAILABLE
    with (
        patch("domain_checker_server.check_dns", new_callable=AsyncMock) as mock_dns,
        patch(
            "domain_checker_server.get_rdap_data", new_callable=AsyncMock
        ) as mock_rdap,
    ):
        mock_dns.return_value = False
        mock_rdap.return_value = ({"errorCode": 404}, 404)
        status, _ = (
            pytest.run(asyncio.run(check_single_domain_availability("available.com")))
            if hasattr(pytest, "run")
            else asyncio.get_event_loop().run_until_complete(
                check_single_domain_availability("available.com")
            )
        )
        assert status == DomainStatus.AVAILABLE


@pytest.mark.asyncio
def test_rdap_logic_unknown_other_status():
    # 422 status => UNKNOWN
    with (
        patch("domain_checker_server.check_dns", new_callable=AsyncMock) as mock_dns,
        patch(
            "domain_checker_server.get_rdap_data", new_callable=AsyncMock
        ) as mock_rdap,
    ):
        mock_dns.return_value = False
        mock_rdap.return_value = ({"errorCode": 422}, 422)
        status, _ = (
            pytest.run(asyncio.run(check_single_domain_availability("weird.com")))
            if hasattr(pytest, "run")
            else asyncio.get_event_loop().run_until_complete(
                check_single_domain_availability("weird.com")
            )
        )
        assert status == DomainStatus.UNKNOWN


@pytest.mark.asyncio
def test_rdap_logic_unreliable_tld():
    # Unreliable TLD, has DNS => REGISTERED
    with (
        patch("domain_checker_server.check_dns", new_callable=AsyncMock) as mock_dns,
        patch(
            "domain_checker_server.get_rdap_data", new_callable=AsyncMock
        ) as mock_rdap,
    ):
        mock_dns.return_value = True
        mock_rdap.return_value = (None, None)
        status, _ = (
            pytest.run(asyncio.run(check_single_domain_availability("something.io")))
            if hasattr(pytest, "run")
            else asyncio.get_event_loop().run_until_complete(
                check_single_domain_availability("something.io")
            )
        )
        assert status == DomainStatus.REGISTERED

    # Unreliable TLD, no DNS => UNKNOWN
    with (
        patch("domain_checker_server.check_dns", new_callable=AsyncMock) as mock_dns,
        patch(
            "domain_checker_server.get_rdap_data", new_callable=AsyncMock
        ) as mock_rdap,
    ):
        mock_dns.return_value = False
        mock_rdap.return_value = (None, None)
        status, _ = (
            pytest.run(asyncio.run(check_single_domain_availability("something.io")))
            if hasattr(pytest, "run")
            else asyncio.get_event_loop().run_until_complete(
                check_single_domain_availability("something.io")
            )
        )
        assert status == DomainStatus.UNKNOWN
