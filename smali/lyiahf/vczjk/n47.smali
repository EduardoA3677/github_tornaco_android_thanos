.class public abstract Llyiahf/vczjk/n47;
.super Llyiahf/vczjk/m49;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/wo1;


# static fields
.field public static final synthetic OooOOOo:I


# instance fields
.field public transient OooOOOO:Ljava/lang/Object;

.field protected final _nuller:Llyiahf/vczjk/u46;

.field protected final _unwrapSingle:Ljava/lang/Boolean;


# direct methods
.method public constructor <init>(Ljava/lang/Class;)V
    .locals 0

    invoke-direct {p0, p1}, Llyiahf/vczjk/m49;-><init>(Ljava/lang/Class;)V

    const/4 p1, 0x0

    iput-object p1, p0, Llyiahf/vczjk/n47;->_unwrapSingle:Ljava/lang/Boolean;

    iput-object p1, p0, Llyiahf/vczjk/n47;->_nuller:Llyiahf/vczjk/u46;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/n47;Llyiahf/vczjk/u46;Ljava/lang/Boolean;)V
    .locals 0

    iget-object p1, p1, Llyiahf/vczjk/m49;->_valueClass:Ljava/lang/Class;

    invoke-direct {p0, p1}, Llyiahf/vczjk/m49;-><init>(Ljava/lang/Class;)V

    iput-object p3, p0, Llyiahf/vczjk/n47;->_unwrapSingle:Ljava/lang/Boolean;

    iput-object p2, p0, Llyiahf/vczjk/n47;->_nuller:Llyiahf/vczjk/u46;

    return-void
.end method


# virtual methods
.method public final OooO()Llyiahf/vczjk/o0OoO00O;
    .locals 1

    sget-object v0, Llyiahf/vczjk/o0OoO00O;->OooOOO:Llyiahf/vczjk/o0OoO00O;

    return-object v0
.end method

.method public final OooO0OO(Llyiahf/vczjk/v72;Llyiahf/vczjk/db0;)Llyiahf/vczjk/e94;
    .locals 4

    iget-object v0, p0, Llyiahf/vczjk/m49;->_valueClass:Ljava/lang/Class;

    sget-object v1, Llyiahf/vczjk/n94;->OooOOO0:Llyiahf/vczjk/n94;

    invoke-static {p1, p2, v0, v1}, Llyiahf/vczjk/m49;->OoooO0O(Llyiahf/vczjk/v72;Llyiahf/vczjk/db0;Ljava/lang/Class;Llyiahf/vczjk/n94;)Ljava/lang/Boolean;

    move-result-object v0

    const/4 v1, 0x0

    if-eqz p2, :cond_0

    invoke-interface {p2}, Llyiahf/vczjk/db0;->OooO0O0()Llyiahf/vczjk/wa7;

    move-result-object v2

    invoke-virtual {v2}, Llyiahf/vczjk/wa7;->OooO0O0()Llyiahf/vczjk/d56;

    move-result-object v2

    goto :goto_0

    :cond_0
    move-object v2, v1

    :goto_0
    sget-object v3, Llyiahf/vczjk/d56;->OooOOO0:Llyiahf/vczjk/d56;

    if-ne v2, v3, :cond_1

    sget-object v1, Llyiahf/vczjk/f56;->OooOOO0:Llyiahf/vczjk/f56;

    goto :goto_1

    :cond_1
    sget-object v3, Llyiahf/vczjk/d56;->OooOOO:Llyiahf/vczjk/d56;

    if-ne v2, v3, :cond_3

    if-nez p2, :cond_2

    iget-object p2, p0, Llyiahf/vczjk/m49;->_valueClass:Ljava/lang/Class;

    invoke-virtual {p2}, Ljava/lang/Class;->getComponentType()Ljava/lang/Class;

    move-result-object p2

    invoke-virtual {p1, p2}, Llyiahf/vczjk/v72;->Oooooo(Ljava/lang/Class;)Llyiahf/vczjk/x64;

    move-result-object p1

    new-instance p2, Llyiahf/vczjk/g56;

    invoke-direct {p2, v1, p1}, Llyiahf/vczjk/g56;-><init>(Llyiahf/vczjk/xa7;Llyiahf/vczjk/x64;)V

    move-object v1, p2

    goto :goto_1

    :cond_2
    invoke-interface {p2}, Llyiahf/vczjk/db0;->getType()Llyiahf/vczjk/x64;

    move-result-object p1

    invoke-virtual {p1}, Llyiahf/vczjk/x64;->Oooo0oo()Llyiahf/vczjk/x64;

    move-result-object p1

    new-instance v1, Llyiahf/vczjk/g56;

    invoke-interface {p2}, Llyiahf/vczjk/db0;->getFullName()Llyiahf/vczjk/xa7;

    move-result-object p2

    invoke-direct {v1, p2, p1}, Llyiahf/vczjk/g56;-><init>(Llyiahf/vczjk/xa7;Llyiahf/vczjk/x64;)V

    :cond_3
    :goto_1
    iget-object p1, p0, Llyiahf/vczjk/n47;->_unwrapSingle:Ljava/lang/Boolean;

    if-ne v0, p1, :cond_4

    iget-object p1, p0, Llyiahf/vczjk/n47;->_nuller:Llyiahf/vczjk/u46;

    if-ne v1, p1, :cond_4

    return-object p0

    :cond_4
    invoke-virtual {p0, v1, v0}, Llyiahf/vczjk/n47;->OoooOoo(Llyiahf/vczjk/u46;Ljava/lang/Boolean;)Llyiahf/vczjk/n47;

    move-result-object p1

    return-object p1
.end method

.method public final OooO0o(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Llyiahf/vczjk/u3a;)Ljava/lang/Object;
    .locals 0

    invoke-virtual {p3, p2, p1}, Llyiahf/vczjk/u3a;->OooO0OO(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final OooO0o0(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    invoke-virtual {p0, p2, p1}, Llyiahf/vczjk/e94;->OooO0Oo(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;

    move-result-object p1

    if-nez p3, :cond_0

    goto :goto_0

    :cond_0
    invoke-static {p3}, Ljava/lang/reflect/Array;->getLength(Ljava/lang/Object;)I

    move-result p2

    if-nez p2, :cond_1

    :goto_0
    return-object p1

    :cond_1
    invoke-virtual {p0, p3, p1}, Llyiahf/vczjk/n47;->OoooOOO(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final OooOO0(Llyiahf/vczjk/v72;)Ljava/lang/Object;
    .locals 0

    iget-object p1, p0, Llyiahf/vczjk/n47;->OooOOOO:Ljava/lang/Object;

    if-nez p1, :cond_0

    invoke-virtual {p0}, Llyiahf/vczjk/n47;->OoooOOo()Ljava/lang/Object;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/n47;->OooOOOO:Ljava/lang/Object;

    :cond_0
    return-object p1
.end method

.method public final OooOOOO(Llyiahf/vczjk/t72;)Ljava/lang/Boolean;
    .locals 0

    sget-object p1, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    return-object p1
.end method

.method public abstract OoooOOO(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
.end method

.method public abstract OoooOOo()Ljava/lang/Object;
.end method

.method public final OoooOo0(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;
    .locals 3

    sget-object v0, Llyiahf/vczjk/gc4;->OooOo00:Llyiahf/vczjk/gc4;

    invoke-virtual {p2, v0}, Llyiahf/vczjk/eb4;->o0000Oo(Llyiahf/vczjk/gc4;)Z

    move-result v0

    const/4 v1, 0x0

    if-eqz v0, :cond_0

    sget-object v0, Llyiahf/vczjk/w72;->Oooo000:Llyiahf/vczjk/w72;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/v72;->o0000(Llyiahf/vczjk/w72;)Z

    move-result v0

    if-eqz v0, :cond_0

    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->o0000oO()Ljava/lang/String;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/String;->length()I

    move-result v0

    if-nez v0, :cond_0

    return-object v1

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/n47;->_unwrapSingle:Ljava/lang/Boolean;

    sget-object v2, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    if-eq v0, v2, :cond_2

    if-nez v0, :cond_1

    sget-object v0, Llyiahf/vczjk/w72;->OooOoo:Llyiahf/vczjk/w72;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/v72;->o0000(Llyiahf/vczjk/w72;)Z

    move-result v0

    if-eqz v0, :cond_1

    goto :goto_0

    :cond_1
    iget-object v0, p0, Llyiahf/vczjk/m49;->_valueClass:Ljava/lang/Class;

    invoke-virtual {p1, v0, p2}, Llyiahf/vczjk/v72;->o000000o(Ljava/lang/Class;Llyiahf/vczjk/eb4;)V

    throw v1

    :cond_2
    :goto_0
    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/n47;->OoooOoO(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public abstract OoooOoO(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;
.end method

.method public abstract OoooOoo(Llyiahf/vczjk/u46;Ljava/lang/Boolean;)Llyiahf/vczjk/n47;
.end method
