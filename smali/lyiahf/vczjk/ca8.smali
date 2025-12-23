.class public final Llyiahf/vczjk/ca8;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $$this$scroll:Llyiahf/vczjk/lz5;

.field final synthetic $previousValue:Llyiahf/vczjk/el7;

.field final synthetic $this_semanticsScrollBy:Llyiahf/vczjk/db8;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/el7;Llyiahf/vczjk/db8;Llyiahf/vczjk/lz5;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/ca8;->$previousValue:Llyiahf/vczjk/el7;

    iput-object p2, p0, Llyiahf/vczjk/ca8;->$this_semanticsScrollBy:Llyiahf/vczjk/db8;

    iput-object p3, p0, Llyiahf/vczjk/ca8;->$$this$scroll:Llyiahf/vczjk/lz5;

    const/4 p1, 0x2

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

    check-cast p1, Ljava/lang/Number;

    invoke-virtual {p1}, Ljava/lang/Number;->floatValue()F

    move-result p1

    check-cast p2, Ljava/lang/Number;

    invoke-virtual {p2}, Ljava/lang/Number;->floatValue()F

    iget-object p2, p0, Llyiahf/vczjk/ca8;->$previousValue:Llyiahf/vczjk/el7;

    iget p2, p2, Llyiahf/vczjk/el7;->element:F

    sub-float/2addr p1, p2

    iget-object p2, p0, Llyiahf/vczjk/ca8;->$this_semanticsScrollBy:Llyiahf/vczjk/db8;

    iget-object v0, p0, Llyiahf/vczjk/ca8;->$$this$scroll:Llyiahf/vczjk/lz5;

    invoke-virtual {p2, p1}, Llyiahf/vczjk/db8;->OooO0OO(F)F

    move-result p1

    invoke-virtual {p2, p1}, Llyiahf/vczjk/db8;->OooO0oO(F)J

    move-result-wide v1

    check-cast v0, Llyiahf/vczjk/za8;

    iget-object p1, v0, Llyiahf/vczjk/za8;->OooO00o:Llyiahf/vczjk/db8;

    iget-object v0, p1, Llyiahf/vczjk/db8;->OooOO0:Llyiahf/vczjk/v98;

    const/4 v3, 0x1

    invoke-static {p1, v0, v1, v2, v3}, Llyiahf/vczjk/db8;->OooO00o(Llyiahf/vczjk/db8;Llyiahf/vczjk/v98;JI)J

    move-result-wide v0

    invoke-virtual {p2, v0, v1}, Llyiahf/vczjk/db8;->OooO0o(J)F

    move-result p1

    invoke-virtual {p2, p1}, Llyiahf/vczjk/db8;->OooO0OO(F)F

    move-result p1

    iget-object p2, p0, Llyiahf/vczjk/ca8;->$previousValue:Llyiahf/vczjk/el7;

    iget v0, p2, Llyiahf/vczjk/el7;->element:F

    add-float/2addr v0, p1

    iput v0, p2, Llyiahf/vczjk/el7;->element:F

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
