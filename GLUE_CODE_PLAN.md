# Missing Glue Code Implementation Plan

## 🎯 **Critical Gaps Identified**

### **Priority 1: Audit Chain Hash Integration** ⚠️
**Impact**: High - Breaks audit integrity guarantees
**Files**: `crates/myc-cli/src/main.rs`, `crates/myc-cli/src/audit.rs`
**Issue**: Multiple audit events use placeholder chain hashes instead of proper hash chaining

**Required Work**:
1. Implement `load_latest_chain_hash()` function
2. Update all audit event creation to use proper chain hashing
3. Fix audit event linking with previous_event_id

### **Priority 2: Vault Metadata Loading** ⚠️
**Impact**: High - Commands can't access actual org context
**Files**: `crates/myc-cli/src/main.rs` (multiple locations)
**Issue**: `TODO: Read from vault.json` - using placeholder OrgId::new()

**Required Work**:
1. Implement `load_org_from_vault()` helper function
2. Replace all placeholder OrgId::new() calls
3. Add proper error handling for missing vault metadata

### **Priority 3: Audit Signature Verification** 🔧
**Impact**: Medium - Audit display incomplete
**Files**: `crates/myc-cli/src/audit.rs`
**Issue**: "verification not implemented" comment

**Required Work**:
1. Implement signature verification in audit display
2. Load device public keys for verification
3. Show verification status in audit output

### **Priority 4: Recovery System** 🔧
**Impact**: Medium - Recovery feature incomplete
**Files**: `crates/myc-core/src/recovery_ops.rs`
**Issue**: Placeholder Shamir's Secret Sharing implementation

**Required Work**:
1. Integrate proper SSS library (e.g., `sharks` crate)
2. Replace placeholder split/reconstruct functions
3. Test recovery workflows end-to-end

### **Priority 5: Audit Index Maintenance** 🔧
**Impact**: Low - Performance optimization
**Files**: `crates/myc-cli/src/audit.rs`
**Issue**: Missing automatic index updates

**Required Work**:
1. Implement audit index update after event creation
2. Add index rebuilding functionality
3. Optimize audit queries using index

## 🚀 **Implementation Strategy**

### **Phase 1: Critical Fixes (High Priority)**
1. **Audit Chain Hash Integration**
   - Create `audit_helpers.rs` module
   - Implement proper chain hash loading/computation
   - Update all audit event creation sites

2. **Vault Metadata Loading**
   - Create `vault_helpers.rs` module  
   - Implement org metadata loading from GitHub
   - Replace all placeholder org ID usage

### **Phase 2: Feature Completion (Medium Priority)**
3. **Audit Signature Verification**
   - Extend audit display with verification
   - Load device keys for signature checking
   - Add verification status indicators

4. **Recovery System Integration**
   - Add `sharks` or similar SSS crate dependency
   - Replace placeholder recovery functions
   - Add comprehensive recovery tests

### **Phase 3: Optimization (Low Priority)**
5. **Audit Index Maintenance**
   - Implement automatic index updates
   - Add index rebuilding commands
   - Optimize audit performance

## 📊 **Current Implementation Status**

- ✅ **Core Cryptography**: Complete and tested
- ✅ **GitHub Integration**: Complete OAuth/OIDC flows
- ✅ **CLI Structure**: All commands implemented
- ✅ **Data Models**: Complete with serialization
- ❌ **Audit Integration**: Missing chain hash glue code
- ❌ **Vault Context**: Missing org metadata loading
- ❌ **Recovery System**: Placeholder implementation
- ⚠️ **Signature Verification**: Partial implementation

## 🎯 **Recommended Next Steps**

1. **Start with Priority 1 & 2** - These are blocking core functionality
2. **Focus on audit chain hash integration first** - Critical for security guarantees
3. **Then fix vault metadata loading** - Needed for proper command context
4. **Recovery system can wait** - Not blocking daily usage
5. **Audit index is optimization** - Can be deferred

The codebase is ~85% complete with solid foundations, but needs these glue code implementations to be production-ready.