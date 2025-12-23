.class public final Llyiahf/vczjk/vv2;
.super Llyiahf/vczjk/o00OO000;
.source "SourceFile"


# instance fields
.field public final OooOOOO:Llyiahf/vczjk/qg;


# direct methods
.method public constructor <init>()V
    .locals 2

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    new-instance v0, Llyiahf/vczjk/qg;

    const/4 v1, 0x3

    invoke-direct {v0, v1}, Llyiahf/vczjk/qg;-><init>(I)V

    iput-object v0, p0, Llyiahf/vczjk/vv2;->OooOOOO:Llyiahf/vczjk/qg;

    return-void
.end method


# virtual methods
.method public final OooO0Oo()Ljava/util/Random;
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/vv2;->OooOOOO:Llyiahf/vczjk/qg;

    invoke-virtual {v0}, Ljava/lang/ThreadLocal;->get()Ljava/lang/Object;

    move-result-object v0

    const-string v1, "get(...)"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v0, Ljava/util/Random;

    return-object v0
.end method
