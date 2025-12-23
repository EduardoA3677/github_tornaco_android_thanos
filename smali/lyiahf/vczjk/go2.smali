.class public final Llyiahf/vczjk/go2;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $alpha:Llyiahf/vczjk/p29;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/p29;"
        }
    .end annotation
.end field

.field final synthetic $scale:Llyiahf/vczjk/p29;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/p29;"
        }
    .end annotation
.end field

.field final synthetic $transformOrigin:Llyiahf/vczjk/p29;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/p29;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Llyiahf/vczjk/ny9;Llyiahf/vczjk/ny9;Llyiahf/vczjk/ny9;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/go2;->$alpha:Llyiahf/vczjk/p29;

    iput-object p2, p0, Llyiahf/vczjk/go2;->$scale:Llyiahf/vczjk/p29;

    iput-object p3, p0, Llyiahf/vczjk/go2;->$transformOrigin:Llyiahf/vczjk/p29;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    check-cast p1, Llyiahf/vczjk/ft7;

    iget-object v0, p0, Llyiahf/vczjk/go2;->$alpha:Llyiahf/vczjk/p29;

    const/high16 v1, 0x3f800000    # 1.0f

    if-eqz v0, :cond_0

    invoke-interface {v0}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/lang/Number;

    invoke-virtual {v0}, Ljava/lang/Number;->floatValue()F

    move-result v0

    goto :goto_0

    :cond_0
    move v0, v1

    :goto_0
    invoke-virtual {p1, v0}, Llyiahf/vczjk/ft7;->OooO00o(F)V

    iget-object v0, p0, Llyiahf/vczjk/go2;->$scale:Llyiahf/vczjk/p29;

    if-eqz v0, :cond_1

    invoke-interface {v0}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/lang/Number;

    invoke-virtual {v0}, Ljava/lang/Number;->floatValue()F

    move-result v0

    goto :goto_1

    :cond_1
    move v0, v1

    :goto_1
    invoke-virtual {p1, v0}, Llyiahf/vczjk/ft7;->OooO0oO(F)V

    iget-object v0, p0, Llyiahf/vczjk/go2;->$scale:Llyiahf/vczjk/p29;

    if-eqz v0, :cond_2

    invoke-interface {v0}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/lang/Number;

    invoke-virtual {v0}, Ljava/lang/Number;->floatValue()F

    move-result v1

    :cond_2
    invoke-virtual {p1, v1}, Llyiahf/vczjk/ft7;->OooOO0O(F)V

    iget-object v0, p0, Llyiahf/vczjk/go2;->$transformOrigin:Llyiahf/vczjk/p29;

    if-eqz v0, :cond_3

    invoke-interface {v0}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/ey9;

    iget-wide v0, v0, Llyiahf/vczjk/ey9;->OooO00o:J

    goto :goto_2

    :cond_3
    sget-wide v0, Llyiahf/vczjk/ey9;->OooO0O0:J

    :goto_2
    invoke-virtual {p1, v0, v1}, Llyiahf/vczjk/ft7;->OooOOo(J)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
