.class public final Llyiahf/vczjk/y49;
.super Llyiahf/vczjk/b59;
.source "SourceFile"


# instance fields
.field public transient OooOOO:Llyiahf/vczjk/gb7;


# direct methods
.method public constructor <init>()V
    .locals 2

    const-class v0, Ljava/lang/String;

    const/4 v1, 0x0

    invoke-direct {p0, v1, v0}, Llyiahf/vczjk/b59;-><init>(ILjava/lang/Class;)V

    sget-object v0, Llyiahf/vczjk/cb7;->OooO00o:Llyiahf/vczjk/cb7;

    iput-object v0, p0, Llyiahf/vczjk/y49;->OooOOO:Llyiahf/vczjk/gb7;

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;)V
    .locals 4

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v0

    iget-object v1, p0, Llyiahf/vczjk/y49;->OooOOO:Llyiahf/vczjk/gb7;

    invoke-virtual {v1, v0}, Llyiahf/vczjk/gb7;->OooO0OO(Ljava/lang/Class;)Llyiahf/vczjk/zb4;

    move-result-object v2

    if-nez v2, :cond_1

    const-class v2, Ljava/lang/Object;

    if-ne v0, v2, :cond_0

    new-instance v2, Llyiahf/vczjk/x49;

    const/16 v3, 0x8

    invoke-direct {v2, v3, v0}, Llyiahf/vczjk/x49;-><init>(ILjava/lang/Class;)V

    invoke-virtual {v1, v0, v2}, Llyiahf/vczjk/gb7;->OooO0O0(Ljava/lang/Class;Llyiahf/vczjk/zb4;)Llyiahf/vczjk/gb7;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/y49;->OooOOO:Llyiahf/vczjk/gb7;

    goto :goto_0

    :cond_0
    iget-object v2, p3, Llyiahf/vczjk/tg8;->_config:Llyiahf/vczjk/gg8;

    invoke-virtual {v2, v0}, Llyiahf/vczjk/ec5;->OooO0Oo(Ljava/lang/Class;)Llyiahf/vczjk/x64;

    move-result-object v2

    const/4 v3, 0x0

    invoke-virtual {p3, v2, v3}, Llyiahf/vczjk/tg8;->o00o0O(Llyiahf/vczjk/x64;Llyiahf/vczjk/db0;)Llyiahf/vczjk/zb4;

    move-result-object v2

    invoke-virtual {v1, v0, v2}, Llyiahf/vczjk/gb7;->OooO0O0(Ljava/lang/Class;Llyiahf/vczjk/zb4;)Llyiahf/vczjk/gb7;

    move-result-object v0

    if-eq v1, v0, :cond_1

    iput-object v0, p0, Llyiahf/vczjk/y49;->OooOOO:Llyiahf/vczjk/gb7;

    :cond_1
    :goto_0
    invoke-virtual {v2, p1, p2, p3}, Llyiahf/vczjk/zb4;->OooO0o(Ljava/lang/Object;Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;)V

    return-void
.end method

.method public readResolve()Ljava/lang/Object;
    .locals 1

    sget-object v0, Llyiahf/vczjk/cb7;->OooO00o:Llyiahf/vczjk/cb7;

    iput-object v0, p0, Llyiahf/vczjk/y49;->OooOOO:Llyiahf/vczjk/gb7;

    return-object p0
.end method
