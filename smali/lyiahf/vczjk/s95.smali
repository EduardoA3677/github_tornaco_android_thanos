.class public final Llyiahf/vczjk/s95;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field final synthetic this$0:Llyiahf/vczjk/w95;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/w95;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/s95;->this$0:Llyiahf/vczjk/w95;

    const/4 p1, 0x0

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/s95;->this$0:Llyiahf/vczjk/w95;

    iget-object v0, v0, Llyiahf/vczjk/w95;->Oooo00O:Llyiahf/vczjk/qs5;

    check-cast v0, Llyiahf/vczjk/fw8;

    invoke-virtual {v0}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/xn4;

    if-eqz v0, :cond_0

    const-wide/16 v1, 0x0

    invoke-interface {v0, v1, v2}, Llyiahf/vczjk/xn4;->OoooOO0(J)J

    move-result-wide v0

    goto :goto_0

    :cond_0
    const-wide v0, 0x7fc000007fc00000L    # 2.247117487993712E307

    :goto_0
    new-instance v2, Llyiahf/vczjk/p86;

    invoke-direct {v2, v0, v1}, Llyiahf/vczjk/p86;-><init>(J)V

    return-object v2
.end method
