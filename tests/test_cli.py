import sys
import pytest
from subdomain.cli import argerror, gitArgError, build_parser


class TestArgerror:
    def test_both_url_and_listfile_exits(self):
        with pytest.raises(SystemExit):
            argerror(url="http://a.com", listfile="urls.txt")

    def test_neither_url_nor_listfile_exits(self):
        with pytest.raises(SystemExit):
            argerror(url=None, listfile=None)

    def test_url_only_passes(self):
        argerror(url="http://a.com", listfile=None)  # should not raise

    def test_listfile_only_passes(self):
        argerror(url=None, listfile="urls.txt")  # should not raise


class TestGitArgError:
    def test_token_without_flag_exits(self):
        with pytest.raises(SystemExit):
            gitArgError(git_token="mytoken", is_git=False)

    def test_flag_without_token_exits(self):
        with pytest.raises(SystemExit):
            gitArgError(git_token=None, is_git=True)

    def test_both_provided_passes(self):
        gitArgError(git_token="mytoken", is_git=True)  # should not raise

    def test_neither_provided_passes(self):
        gitArgError(git_token=None, is_git=False)  # should not raise


class TestBuildParser:
    def test_parser_returns_argparse_namespace(self):
        parser = build_parser()
        args = parser.parse_args(['-u', 'http://example.com'])
        assert args.url == 'http://example.com'

    def test_parser_nossl_flag(self):
        parser = build_parser()
        args = parser.parse_args(['-u', 'http://example.com', '-k'])
        assert args.nossl is True

    def test_parser_gitscan_flag(self):
        parser = build_parser()
        args = parser.parse_args(['-u', 'http://example.com', '-g', '-gt', 'tok'])
        assert args.gitscan is True
        assert args.gittoken == 'tok'
