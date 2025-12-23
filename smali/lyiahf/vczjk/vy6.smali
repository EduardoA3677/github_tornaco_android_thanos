.class public final Llyiahf/vczjk/vy6;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/bf3;


# instance fields
.field final synthetic $onTouchEvent:Llyiahf/vczjk/oe3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/oe3;"
        }
    .end annotation
.end field

.field final synthetic $requestDisallowInterceptTouchEvent:Llyiahf/vczjk/er7;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/oe3;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/vy6;->$onTouchEvent:Llyiahf/vczjk/oe3;

    const/4 p1, 0x0

    iput-object p1, p0, Llyiahf/vczjk/vy6;->$requestDisallowInterceptTouchEvent:Llyiahf/vczjk/er7;

    const/4 p1, 0x3

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o0(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    check-cast p1, Llyiahf/vczjk/kl5;

    check-cast p2, Llyiahf/vczjk/rf1;

    check-cast p3, Ljava/lang/Number;

    invoke-virtual {p3}, Ljava/lang/Number;->intValue()I

    check-cast p2, Llyiahf/vczjk/zf1;

    const p1, 0x1650851b

    invoke-virtual {p2, p1}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {p2}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object p1

    sget-object p3, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-ne p1, p3, :cond_0

    new-instance p1, Llyiahf/vczjk/uy6;

    invoke-direct {p1}, Llyiahf/vczjk/uy6;-><init>()V

    invoke-virtual {p2, p1}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_0
    check-cast p1, Llyiahf/vczjk/uy6;

    iget-object p3, p0, Llyiahf/vczjk/vy6;->$onTouchEvent:Llyiahf/vczjk/oe3;

    iput-object p3, p1, Llyiahf/vczjk/uy6;->OooOOO0:Llyiahf/vczjk/oe3;

    iget-object p3, p0, Llyiahf/vczjk/vy6;->$requestDisallowInterceptTouchEvent:Llyiahf/vczjk/er7;

    iget-object v0, p1, Llyiahf/vczjk/uy6;->OooOOO:Llyiahf/vczjk/er7;

    if-nez v0, :cond_1

    goto :goto_0

    :cond_1
    const/4 v1, 0x0

    iput-object v1, v0, Llyiahf/vczjk/er7;->OooOOO0:Llyiahf/vczjk/uy6;

    :goto_0
    iput-object p3, p1, Llyiahf/vczjk/uy6;->OooOOO:Llyiahf/vczjk/er7;

    if-nez p3, :cond_2

    goto :goto_1

    :cond_2
    iput-object p1, p3, Llyiahf/vczjk/er7;->OooOOO0:Llyiahf/vczjk/uy6;

    :goto_1
    const/4 p3, 0x0

    invoke-virtual {p2, p3}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    return-object p1
.end method
