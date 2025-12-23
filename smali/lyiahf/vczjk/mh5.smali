.class public final Llyiahf/vczjk/mh5;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $alpha$delegate:Llyiahf/vczjk/p29;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/p29;"
        }
    .end annotation
.end field

.field final synthetic $scale$delegate:Llyiahf/vczjk/p29;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/p29;"
        }
    .end annotation
.end field

.field final synthetic $transformOriginState:Llyiahf/vczjk/qs5;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/qs5;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Llyiahf/vczjk/qs5;Llyiahf/vczjk/uy9;Llyiahf/vczjk/uy9;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/mh5;->$transformOriginState:Llyiahf/vczjk/qs5;

    iput-object p2, p0, Llyiahf/vczjk/mh5;->$scale$delegate:Llyiahf/vczjk/p29;

    iput-object p3, p0, Llyiahf/vczjk/mh5;->$alpha$delegate:Llyiahf/vczjk/p29;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    check-cast p1, Llyiahf/vczjk/ft7;

    iget-object v0, p0, Llyiahf/vczjk/mh5;->$scale$delegate:Llyiahf/vczjk/p29;

    invoke-interface {v0}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/lang/Number;

    invoke-virtual {v0}, Ljava/lang/Number;->floatValue()F

    move-result v0

    invoke-virtual {p1, v0}, Llyiahf/vczjk/ft7;->OooO0oO(F)V

    iget-object v0, p0, Llyiahf/vczjk/mh5;->$scale$delegate:Llyiahf/vczjk/p29;

    invoke-interface {v0}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/lang/Number;

    invoke-virtual {v0}, Ljava/lang/Number;->floatValue()F

    move-result v0

    invoke-virtual {p1, v0}, Llyiahf/vczjk/ft7;->OooOO0O(F)V

    iget-object v0, p0, Llyiahf/vczjk/mh5;->$alpha$delegate:Llyiahf/vczjk/p29;

    invoke-interface {v0}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/lang/Number;

    invoke-virtual {v0}, Ljava/lang/Number;->floatValue()F

    move-result v0

    invoke-virtual {p1, v0}, Llyiahf/vczjk/ft7;->OooO00o(F)V

    iget-object v0, p0, Llyiahf/vczjk/mh5;->$transformOriginState:Llyiahf/vczjk/qs5;

    invoke-interface {v0}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/ey9;

    iget-wide v0, v0, Llyiahf/vczjk/ey9;->OooO00o:J

    invoke-virtual {p1, v0, v1}, Llyiahf/vczjk/ft7;->OooOOo(J)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
