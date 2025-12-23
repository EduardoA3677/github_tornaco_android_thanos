.class public final Llyiahf/vczjk/nm6;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $previousValue:Llyiahf/vczjk/el7;

.field final synthetic $this_animateScrollToPage:Llyiahf/vczjk/qu4;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/el7;Llyiahf/vczjk/sl6;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/nm6;->$previousValue:Llyiahf/vczjk/el7;

    iput-object p2, p0, Llyiahf/vczjk/nm6;->$this_animateScrollToPage:Llyiahf/vczjk/qu4;

    const/4 p1, 0x2

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    check-cast p1, Ljava/lang/Number;

    invoke-virtual {p1}, Ljava/lang/Number;->floatValue()F

    move-result p1

    check-cast p2, Ljava/lang/Number;

    invoke-virtual {p2}, Ljava/lang/Number;->floatValue()F

    iget-object p2, p0, Llyiahf/vczjk/nm6;->$previousValue:Llyiahf/vczjk/el7;

    iget p2, p2, Llyiahf/vczjk/el7;->element:F

    sub-float/2addr p1, p2

    iget-object p2, p0, Llyiahf/vczjk/nm6;->$this_animateScrollToPage:Llyiahf/vczjk/qu4;

    check-cast p2, Llyiahf/vczjk/sl6;

    iget-object p2, p2, Llyiahf/vczjk/sl6;->OooO00o:Llyiahf/vczjk/v98;

    invoke-interface {p2, p1}, Llyiahf/vczjk/v98;->OooO00o(F)F

    move-result p1

    iget-object p2, p0, Llyiahf/vczjk/nm6;->$previousValue:Llyiahf/vczjk/el7;

    iget v0, p2, Llyiahf/vczjk/el7;->element:F

    add-float/2addr v0, p1

    iput v0, p2, Llyiahf/vczjk/el7;->element:F

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
