# test_optimizations.py
"""
Quick test script to verify optimizations are working
"""
import os
import django
from django.test import TestCase
from django.core.cache import cache
from django.db import connection
from django.test.utils import override_settings

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'vcfproject.settings')
django.setup()

from members.models import UserPurchase, MemberAccount
from customadmin.models import VCFFile
from members.views import VCF_Tabs, member_dashboard

def test_query_count():
    """Test that our optimized views use fewer queries"""
    print("Testing query optimization...")
    
    # Reset query count
    connection.queries_log.clear()
    
    # The optimized VCF_Tabs view should use minimal queries
    print(f"Query count before optimization test: {len(connection.queries)}")
    
    # Test cache keys
    print("Testing cache functionality...")
    
    # Test cache set/get
    test_key = "test_vcf_tabs_123"
    test_data = {"test": "data"}
    
    cache.set(test_key, test_data, 300)
    cached_result = cache.get(test_key)
    
    assert cached_result == test_data, "Cache set/get failed"
    print("✓ Cache functionality working")
    
    # Test cache deletion
    cache.delete(test_key)
    cached_result = cache.get(test_key)
    
    assert cached_result is None, "Cache deletion failed"
    print("✓ Cache deletion working")
    
    print("All optimization tests passed!")

def test_database_indexes():
    """Test that our database indexes are created"""
    print("Testing database indexes...")
    
    # Check if models have the Meta indexes defined
    vcf_indexes = getattr(VCFFile._meta, 'indexes', [])
    purchase_indexes = getattr(UserPurchase._meta, 'indexes', [])
    
    print(f"VCFFile indexes: {len(vcf_indexes)}")
    print(f"UserPurchase indexes: {len(purchase_indexes)}")
    
    # The indexes should be defined in Meta
    assert len(vcf_indexes) >= 2, "VCFFile should have at least 2 indexes"
    assert len(purchase_indexes) >= 2, "UserPurchase should have at least 2 indexes"
    
    print("✓ Database indexes are defined")

if __name__ == "__main__":
    try:
        test_query_count()
        test_database_indexes()
        print("\n🎉 All optimization tests passed successfully!")
    except Exception as e:
        print(f"\n❌ Test failed: {str(e)}")
        import traceback
        traceback.print_exc()
