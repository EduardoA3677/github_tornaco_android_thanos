.class public final Llyiahf/vczjk/vf2;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $$this$drag:Llyiahf/vczjk/of2;

.field final synthetic this$0:Llyiahf/vczjk/zf2;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/of2;Llyiahf/vczjk/zf2;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/vf2;->$$this$drag:Llyiahf/vczjk/of2;

    iput-object p2, p0, Llyiahf/vczjk/vf2;->this$0:Llyiahf/vczjk/zf2;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 5

    check-cast p1, Llyiahf/vczjk/ke2;

    iget-object v0, p0, Llyiahf/vczjk/vf2;->$$this$drag:Llyiahf/vczjk/of2;

    iget-object v1, p0, Llyiahf/vczjk/vf2;->this$0:Llyiahf/vczjk/zf2;

    iget-wide v2, p1, Llyiahf/vczjk/ke2;->OooO00o:J

    iget-boolean p1, v1, Llyiahf/vczjk/zf2;->Oooo:Z

    if-eqz p1, :cond_0

    const/high16 p1, -0x40800000    # -1.0f

    :goto_0
    invoke-static {p1, v2, v3}, Llyiahf/vczjk/p86;->OooO0oO(FJ)J

    move-result-wide v1

    goto :goto_1

    :cond_0
    const/high16 p1, 0x3f800000    # 1.0f

    goto :goto_0

    :goto_1
    iget-object p1, p0, Llyiahf/vczjk/vf2;->this$0:Llyiahf/vczjk/zf2;

    iget-object p1, p1, Llyiahf/vczjk/zf2;->Oooo0o0:Llyiahf/vczjk/nf6;

    sget-object v3, Llyiahf/vczjk/uf2;->OooO00o:Llyiahf/vczjk/rf2;

    sget-object v3, Llyiahf/vczjk/nf6;->OooOOO0:Llyiahf/vczjk/nf6;

    if-ne p1, v3, :cond_1

    const-wide v3, 0xffffffffL

    and-long/2addr v1, v3

    :goto_2
    long-to-int p1, v1

    invoke-static {p1}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result p1

    goto :goto_3

    :cond_1
    const/16 p1, 0x20

    shr-long/2addr v1, p1

    goto :goto_2

    :goto_3
    invoke-interface {v0, p1}, Llyiahf/vczjk/of2;->OooO00o(F)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
