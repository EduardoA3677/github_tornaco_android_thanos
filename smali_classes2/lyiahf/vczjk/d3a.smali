.class public final Llyiahf/vczjk/d3a;
.super Llyiahf/vczjk/k10;
.source "SourceFile"


# static fields
.field public static final OooOOO:Llyiahf/vczjk/xo8;

.field public static final OooOOOO:Llyiahf/vczjk/d3a;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    new-instance v0, Llyiahf/vczjk/xo8;

    const/4 v1, 0x5

    invoke-direct {v0, v1}, Llyiahf/vczjk/xo8;-><init>(I)V

    sput-object v0, Llyiahf/vczjk/d3a;->OooOOO:Llyiahf/vczjk/xo8;

    new-instance v0, Llyiahf/vczjk/d3a;

    sget-object v1, Llyiahf/vczjk/an2;->OooOOO0:Llyiahf/vczjk/an2;

    invoke-direct {v0, v1}, Llyiahf/vczjk/d3a;-><init>(Ljava/util/List;)V

    sput-object v0, Llyiahf/vczjk/d3a;->OooOOOO:Llyiahf/vczjk/d3a;

    return-void
.end method

.method public constructor <init>(Ljava/util/List;)V
    .locals 7

    sget-object v0, Llyiahf/vczjk/rm2;->OooOOO0:Llyiahf/vczjk/rm2;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object v0, p0, Llyiahf/vczjk/k10;->OooOOO0:Llyiahf/vczjk/gy;

    invoke-interface {p1}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    move-result-object p1

    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    move-result v0

    if-eqz v0, :cond_4

    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/qo;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v1, Llyiahf/vczjk/ym7;->OooO00o:Llyiahf/vczjk/zm7;

    const-class v2, Llyiahf/vczjk/qo;

    invoke-virtual {v1, v2}, Llyiahf/vczjk/zm7;->OooO0O0(Ljava/lang/Class;)Llyiahf/vczjk/gf4;

    move-result-object v1

    invoke-interface {v1}, Llyiahf/vczjk/gf4;->OooO00o()Ljava/lang/String;

    move-result-object v1

    invoke-static {v1}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    sget-object v2, Llyiahf/vczjk/d3a;->OooOOO:Llyiahf/vczjk/xo8;

    invoke-virtual {v2, v1}, Llyiahf/vczjk/xo8;->OooO(Ljava/lang/String;)I

    move-result v1

    iget-object v2, p0, Llyiahf/vczjk/k10;->OooOOO0:Llyiahf/vczjk/gy;

    invoke-virtual {v2}, Llyiahf/vczjk/gy;->OooO00o()I

    move-result v2

    const/4 v3, 0x0

    if-eqz v2, :cond_2

    const/4 v4, 0x1

    if-eq v2, v4, :cond_0

    goto :goto_1

    :cond_0
    iget-object v2, p0, Llyiahf/vczjk/k10;->OooOOO0:Llyiahf/vczjk/gy;

    :try_start_0
    const-string v5, "null cannot be cast to non-null type org.jetbrains.kotlin.util.OneElementArrayMap<T of org.jetbrains.kotlin.util.AttributeArrayOwner>"

    invoke-static {v2, v5}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v2, Llyiahf/vczjk/pb6;
    :try_end_0
    .catch Ljava/lang/ClassCastException; {:try_start_0 .. :try_end_0} :catch_0

    iget v4, v2, Llyiahf/vczjk/pb6;->OooOOO:I

    if-ne v4, v1, :cond_1

    new-instance v2, Llyiahf/vczjk/pb6;

    invoke-direct {v2, v1, v0}, Llyiahf/vczjk/pb6;-><init>(ILlyiahf/vczjk/qo;)V

    iput-object v2, p0, Llyiahf/vczjk/k10;->OooOOO0:Llyiahf/vczjk/gy;

    goto :goto_0

    :cond_1
    new-instance v5, Llyiahf/vczjk/jy;

    const/16 v6, 0x14

    new-array v6, v6, [Ljava/lang/Object;

    invoke-direct {v5}, Ljava/lang/Object;-><init>()V

    iput-object v6, v5, Llyiahf/vczjk/jy;->OooOOO0:[Ljava/lang/Object;

    iput v3, v5, Llyiahf/vczjk/jy;->OooOOO:I

    iget-object v2, v2, Llyiahf/vczjk/pb6;->OooOOO0:Llyiahf/vczjk/qo;

    invoke-virtual {v5, v4, v2}, Llyiahf/vczjk/jy;->OooO0O0(ILlyiahf/vczjk/qo;)V

    iput-object v5, p0, Llyiahf/vczjk/k10;->OooOOO0:Llyiahf/vczjk/gy;

    :goto_1
    iget-object v2, p0, Llyiahf/vczjk/k10;->OooOOO0:Llyiahf/vczjk/gy;

    invoke-virtual {v2, v1, v0}, Llyiahf/vczjk/gy;->OooO0O0(ILlyiahf/vczjk/qo;)V

    goto :goto_0

    :catch_0
    move-exception p1

    new-instance v0, Ljava/lang/IllegalStateException;

    const-string v1, "OneElementArrayMap"

    invoke-static {v2, v4, v1}, Llyiahf/vczjk/k10;->OooO00o(Llyiahf/vczjk/gy;ILjava/lang/String;)Ljava/lang/String;

    move-result-object v1

    invoke-direct {v0, v1, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    throw v0

    :cond_2
    iget-object v2, p0, Llyiahf/vczjk/k10;->OooOOO0:Llyiahf/vczjk/gy;

    instance-of v4, v2, Llyiahf/vczjk/rm2;

    if-eqz v4, :cond_3

    new-instance v2, Llyiahf/vczjk/pb6;

    invoke-direct {v2, v1, v0}, Llyiahf/vczjk/pb6;-><init>(ILlyiahf/vczjk/qo;)V

    iput-object v2, p0, Llyiahf/vczjk/k10;->OooOOO0:Llyiahf/vczjk/gy;

    goto :goto_0

    :cond_3
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "EmptyArrayMap"

    invoke-static {v2, v3, v0}, Llyiahf/vczjk/k10;->OooO00o(Llyiahf/vczjk/gy;ILjava/lang/String;)Ljava/lang/String;

    move-result-object v0

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_4
    return-void
.end method
