.class public final Llyiahf/vczjk/j22;
.super Llyiahf/vczjk/pl2;
.source "SourceFile"


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/tg7;

.field public final synthetic OooOOO0:Llyiahf/vczjk/qs5;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/qs5;Llyiahf/vczjk/tg7;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/j22;->OooOOO0:Llyiahf/vczjk/qs5;

    iput-object p2, p0, Llyiahf/vczjk/j22;->OooOOO:Llyiahf/vczjk/tg7;

    return-void
.end method


# virtual methods
.method public final OooO00o()V
    .locals 2

    sget-object v0, Llyiahf/vczjk/m6a;->OooO0O0:Llyiahf/vczjk/xv3;

    iget-object v1, p0, Llyiahf/vczjk/j22;->OooOOO:Llyiahf/vczjk/tg7;

    iput-object v0, v1, Llyiahf/vczjk/tg7;->OooOOO:Ljava/lang/Object;

    return-void
.end method

.method public final OooO0O0()V
    .locals 2

    sget-object v0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    iget-object v1, p0, Llyiahf/vczjk/j22;->OooOOO0:Llyiahf/vczjk/qs5;

    check-cast v1, Llyiahf/vczjk/fw8;

    invoke-virtual {v1, v0}, Llyiahf/vczjk/fw8;->setValue(Ljava/lang/Object;)V

    new-instance v0, Llyiahf/vczjk/xv3;

    const/4 v1, 0x1

    invoke-direct {v0, v1}, Llyiahf/vczjk/xv3;-><init>(Z)V

    iget-object v1, p0, Llyiahf/vczjk/j22;->OooOOO:Llyiahf/vczjk/tg7;

    iput-object v0, v1, Llyiahf/vczjk/tg7;->OooOOO:Ljava/lang/Object;

    return-void
.end method
