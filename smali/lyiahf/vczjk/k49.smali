.class public final Llyiahf/vczjk/k49;
.super Llyiahf/vczjk/m49;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/wo1;
.implements Llyiahf/vczjk/nr7;


# static fields
.field private static final serialVersionUID:J = 0x1L


# instance fields
.field protected final _converter:Llyiahf/vczjk/gp1;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/gp1;"
        }
    .end annotation
.end field

.field protected final _delegateDeserializer:Llyiahf/vczjk/e94;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/e94;"
        }
    .end annotation
.end field

.field protected final _delegateType:Llyiahf/vczjk/x64;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/gp1;Llyiahf/vczjk/x64;Llyiahf/vczjk/e94;)V
    .locals 0

    invoke-direct {p0, p2}, Llyiahf/vczjk/m49;-><init>(Llyiahf/vczjk/x64;)V

    iput-object p1, p0, Llyiahf/vczjk/k49;->_converter:Llyiahf/vczjk/gp1;

    iput-object p2, p0, Llyiahf/vczjk/k49;->_delegateType:Llyiahf/vczjk/x64;

    iput-object p3, p0, Llyiahf/vczjk/k49;->_delegateDeserializer:Llyiahf/vczjk/e94;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/j74;)V
    .locals 1

    const-class v0, Ljava/lang/Object;

    invoke-direct {p0, v0}, Llyiahf/vczjk/m49;-><init>(Ljava/lang/Class;)V

    iput-object p1, p0, Llyiahf/vczjk/k49;->_converter:Llyiahf/vczjk/gp1;

    const/4 p1, 0x0

    iput-object p1, p0, Llyiahf/vczjk/k49;->_delegateType:Llyiahf/vczjk/x64;

    iput-object p1, p0, Llyiahf/vczjk/k49;->_delegateDeserializer:Llyiahf/vczjk/e94;

    return-void
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/v72;)V
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/k49;->_delegateDeserializer:Llyiahf/vczjk/e94;

    if-eqz v0, :cond_0

    instance-of v1, v0, Llyiahf/vczjk/nr7;

    if-eqz v1, :cond_0

    check-cast v0, Llyiahf/vczjk/nr7;

    invoke-interface {v0, p1}, Llyiahf/vczjk/nr7;->OooO00o(Llyiahf/vczjk/v72;)V

    :cond_0
    return-void
.end method

.method public final OooO0OO(Llyiahf/vczjk/v72;Llyiahf/vczjk/db0;)Llyiahf/vczjk/e94;
    .locals 4

    iget-object v0, p0, Llyiahf/vczjk/k49;->_delegateDeserializer:Llyiahf/vczjk/e94;

    const-string v1, "withDelegate"

    const-class v2, Llyiahf/vczjk/k49;

    if-eqz v0, :cond_1

    iget-object v3, p0, Llyiahf/vczjk/k49;->_delegateType:Llyiahf/vczjk/x64;

    invoke-virtual {p1, v0, p2, v3}, Llyiahf/vczjk/v72;->o000000O(Llyiahf/vczjk/e94;Llyiahf/vczjk/db0;Llyiahf/vczjk/x64;)Llyiahf/vczjk/e94;

    move-result-object p1

    iget-object p2, p0, Llyiahf/vczjk/k49;->_delegateDeserializer:Llyiahf/vczjk/e94;

    if-eq p1, p2, :cond_0

    iget-object p2, p0, Llyiahf/vczjk/k49;->_converter:Llyiahf/vczjk/gp1;

    iget-object v0, p0, Llyiahf/vczjk/k49;->_delegateType:Llyiahf/vczjk/x64;

    invoke-static {v2, p0, v1}, Llyiahf/vczjk/vy0;->OooOoOO(Ljava/lang/Class;Ljava/io/Serializable;Ljava/lang/String;)V

    new-instance v1, Llyiahf/vczjk/k49;

    invoke-direct {v1, p2, v0, p1}, Llyiahf/vczjk/k49;-><init>(Llyiahf/vczjk/gp1;Llyiahf/vczjk/x64;Llyiahf/vczjk/e94;)V

    return-object v1

    :cond_0
    return-object p0

    :cond_1
    iget-object v0, p0, Llyiahf/vczjk/k49;->_converter:Llyiahf/vczjk/gp1;

    invoke-virtual {p1}, Llyiahf/vczjk/v72;->Oooo0o0()Llyiahf/vczjk/a4a;

    check-cast v0, Llyiahf/vczjk/j74;

    iget-object v0, v0, Llyiahf/vczjk/j74;->OooO00o:Llyiahf/vczjk/x64;

    iget-object v3, p0, Llyiahf/vczjk/k49;->_converter:Llyiahf/vczjk/gp1;

    invoke-virtual {p1, v0, p2}, Llyiahf/vczjk/v72;->o0OoOo0(Llyiahf/vczjk/x64;Llyiahf/vczjk/db0;)Llyiahf/vczjk/e94;

    move-result-object p1

    invoke-static {v2, p0, v1}, Llyiahf/vczjk/vy0;->OooOoOO(Ljava/lang/Class;Ljava/io/Serializable;Ljava/lang/String;)V

    new-instance p2, Llyiahf/vczjk/k49;

    invoke-direct {p2, v3, v0, p1}, Llyiahf/vczjk/k49;-><init>(Llyiahf/vczjk/gp1;Llyiahf/vczjk/x64;Llyiahf/vczjk/e94;)V

    return-object p2
.end method

.method public final OooO0Oo(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/k49;->_delegateDeserializer:Llyiahf/vczjk/e94;

    invoke-virtual {v0, p1, p2}, Llyiahf/vczjk/e94;->OooO0Oo(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;

    move-result-object p1

    if-nez p1, :cond_0

    const/4 p1, 0x0

    return-object p1

    :cond_0
    iget-object p2, p0, Llyiahf/vczjk/k49;->_converter:Llyiahf/vczjk/gp1;

    check-cast p2, Llyiahf/vczjk/j74;

    invoke-virtual {p2, p1}, Llyiahf/vczjk/j74;->OooO0O0(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final OooO0o(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Llyiahf/vczjk/u3a;)Ljava/lang/Object;
    .locals 0

    iget-object p3, p0, Llyiahf/vczjk/k49;->_delegateDeserializer:Llyiahf/vczjk/e94;

    invoke-virtual {p3, p2, p1}, Llyiahf/vczjk/e94;->OooO0Oo(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;

    move-result-object p1

    if-nez p1, :cond_0

    const/4 p1, 0x0

    return-object p1

    :cond_0
    iget-object p2, p0, Llyiahf/vczjk/k49;->_converter:Llyiahf/vczjk/gp1;

    check-cast p2, Llyiahf/vczjk/j74;

    invoke-virtual {p2, p1}, Llyiahf/vczjk/j74;->OooO0O0(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final OooO0o0(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/k49;->_delegateType:Llyiahf/vczjk/x64;

    invoke-virtual {v0}, Llyiahf/vczjk/x64;->OoooO()Ljava/lang/Class;

    move-result-object v0

    invoke-virtual {p3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    move-result v0

    if-eqz v0, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/k49;->_delegateDeserializer:Llyiahf/vczjk/e94;

    invoke-virtual {v0, p1, p2, p3}, Llyiahf/vczjk/e94;->OooO0o0(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1

    :cond_0
    new-instance p1, Ljava/lang/UnsupportedOperationException;

    invoke-virtual {p3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object p2

    invoke-virtual {p2}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object p2

    const-string p3, "Cannot update object of type %s (using deserializer for type %s)"

    invoke-virtual {p3, p2}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    move-result-object p2

    iget-object p3, p0, Llyiahf/vczjk/k49;->_delegateType:Llyiahf/vczjk/x64;

    filled-new-array {p3}, [Ljava/lang/Object;

    move-result-object p3

    invoke-static {p2, p3}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object p2

    invoke-direct {p1, p2}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    throw p1
.end method

.method public final OooOOO0()Ljava/lang/Class;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/k49;->_delegateDeserializer:Llyiahf/vczjk/e94;

    invoke-virtual {v0}, Llyiahf/vczjk/e94;->OooOOO0()Ljava/lang/Class;

    move-result-object v0

    return-object v0
.end method

.method public final OooOOOO(Llyiahf/vczjk/t72;)Ljava/lang/Boolean;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/k49;->_delegateDeserializer:Llyiahf/vczjk/e94;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/e94;->OooOOOO(Llyiahf/vczjk/t72;)Ljava/lang/Boolean;

    move-result-object p1

    return-object p1
.end method
