.class public final Llyiahf/vczjk/hk0;
.super Llyiahf/vczjk/ih6;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/hh6;


# instance fields
.field public final OooOo:Llyiahf/vczjk/pb7;

.field public final OooOo0O:Llyiahf/vczjk/ck0;

.field public final OooOo0o:Llyiahf/vczjk/n62;

.field public OooOoO:Llyiahf/vczjk/s82;

.field public OooOoO0:Llyiahf/vczjk/vc7;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/hc3;Llyiahf/vczjk/q45;Llyiahf/vczjk/cm5;Llyiahf/vczjk/vc7;Llyiahf/vczjk/ck0;)V
    .locals 2

    const-string p2, "fqName"

    invoke-static {p1, p2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string p2, "module"

    invoke-static {p3, p2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string p2, "metadataVersion"

    invoke-static {p5, p2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p0, p3, p1}, Llyiahf/vczjk/ih6;-><init>(Llyiahf/vczjk/cm5;Llyiahf/vczjk/hc3;)V

    iput-object p5, p0, Llyiahf/vczjk/hk0;->OooOo0O:Llyiahf/vczjk/ck0;

    new-instance p1, Llyiahf/vczjk/n62;

    invoke-virtual {p4}, Llyiahf/vczjk/vc7;->OooOo()Llyiahf/vczjk/cd7;

    move-result-object p2

    const-string p3, "getStrings(...)"

    invoke-static {p2, p3}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {p4}, Llyiahf/vczjk/vc7;->OooOo0o()Llyiahf/vczjk/bd7;

    move-result-object p3

    const-string v0, "getQualifiedNames(...)"

    invoke-static {p3, v0}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    const/16 v0, 0x18

    const/4 v1, 0x0

    invoke-direct {p1, v0, p2, p3, v1}, Llyiahf/vczjk/n62;-><init>(ILjava/lang/Object;Ljava/lang/Object;Z)V

    iput-object p1, p0, Llyiahf/vczjk/hk0;->OooOo0o:Llyiahf/vczjk/n62;

    new-instance p2, Llyiahf/vczjk/pb7;

    new-instance p3, Llyiahf/vczjk/oo000o;

    const/16 v0, 0xb

    invoke-direct {p3, p0, v0}, Llyiahf/vczjk/oo000o;-><init>(Ljava/lang/Object;I)V

    invoke-direct {p2, p4, p1, p5, p3}, Llyiahf/vczjk/pb7;-><init>(Llyiahf/vczjk/vc7;Llyiahf/vczjk/n62;Llyiahf/vczjk/ck0;Llyiahf/vczjk/oo000o;)V

    iput-object p2, p0, Llyiahf/vczjk/hk0;->OooOo:Llyiahf/vczjk/pb7;

    iput-object p4, p0, Llyiahf/vczjk/hk0;->OooOoO0:Llyiahf/vczjk/vc7;

    return-void
.end method


# virtual methods
.method public final OoooOO0()Llyiahf/vczjk/jg5;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/hk0;->OooOoO:Llyiahf/vczjk/s82;

    if-eqz v0, :cond_0

    return-object v0

    :cond_0
    const-string v0, "_memberScope"

    invoke-static {v0}, Llyiahf/vczjk/v34;->Ooooooo(Ljava/lang/String;)V

    const/4 v0, 0x0

    throw v0
.end method

.method public final o0000O0O(Llyiahf/vczjk/s72;)V
    .locals 11

    const-string v0, "components"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Llyiahf/vczjk/hk0;->OooOoO0:Llyiahf/vczjk/vc7;

    if-eqz v0, :cond_0

    const/4 v1, 0x0

    iput-object v1, p0, Llyiahf/vczjk/hk0;->OooOoO0:Llyiahf/vczjk/vc7;

    new-instance v2, Llyiahf/vczjk/s82;

    invoke-virtual {v0}, Llyiahf/vczjk/vc7;->OooOo0O()Llyiahf/vczjk/tc7;

    move-result-object v4

    const-string v0, "getPackage(...)"

    invoke-static {v4, v0}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "scope of "

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v9

    new-instance v10, Llyiahf/vczjk/o0oOOo;

    const/16 v0, 0xa

    invoke-direct {v10, p0, v0}, Llyiahf/vczjk/o0oOOo;-><init>(Ljava/lang/Object;I)V

    iget-object v6, p0, Llyiahf/vczjk/hk0;->OooOo0O:Llyiahf/vczjk/ck0;

    const/4 v7, 0x0

    iget-object v5, p0, Llyiahf/vczjk/hk0;->OooOo0o:Llyiahf/vczjk/n62;

    move-object v3, p0

    move-object v8, p1

    invoke-direct/range {v2 .. v10}, Llyiahf/vczjk/s82;-><init>(Llyiahf/vczjk/hh6;Llyiahf/vczjk/tc7;Llyiahf/vczjk/rt5;Llyiahf/vczjk/zb0;Llyiahf/vczjk/ce4;Llyiahf/vczjk/s72;Ljava/lang/String;Llyiahf/vczjk/le3;)V

    iput-object v2, v3, Llyiahf/vczjk/hk0;->OooOoO:Llyiahf/vczjk/s82;

    return-void

    :cond_0
    move-object v3, p0

    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "Repeated call to DeserializedPackageFragmentImpl::initialize"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "builtins package fragment for "

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    iget-object v1, p0, Llyiahf/vczjk/ih6;->OooOo00:Llyiahf/vczjk/hc3;

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v1, " from "

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-static {p0}, Llyiahf/vczjk/p72;->OooOO0(Llyiahf/vczjk/v02;)Llyiahf/vczjk/cm5;

    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
