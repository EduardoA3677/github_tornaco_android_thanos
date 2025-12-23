.class public final Llyiahf/vczjk/q7;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $$this$anchoredDrag:Llyiahf/vczjk/k7;

.field final synthetic $prev:Llyiahf/vczjk/el7;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/k7;Llyiahf/vczjk/el7;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/q7;->$$this$anchoredDrag:Llyiahf/vczjk/k7;

    iput-object p2, p0, Llyiahf/vczjk/q7;->$prev:Llyiahf/vczjk/el7;

    const/4 p1, 0x2

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    check-cast p1, Ljava/lang/Number;

    invoke-virtual {p1}, Ljava/lang/Number;->floatValue()F

    move-result p1

    check-cast p2, Ljava/lang/Number;

    invoke-virtual {p2}, Ljava/lang/Number;->floatValue()F

    move-result p2

    iget-object v0, p0, Llyiahf/vczjk/q7;->$$this$anchoredDrag:Llyiahf/vczjk/k7;

    check-cast v0, Llyiahf/vczjk/s8;

    iget-object v0, v0, Llyiahf/vczjk/s8;->OooO00o:Llyiahf/vczjk/d9;

    iget-object v1, v0, Llyiahf/vczjk/d9;->OooOO0:Llyiahf/vczjk/lr5;

    check-cast v1, Llyiahf/vczjk/zv8;

    invoke-virtual {v1, p1}, Llyiahf/vczjk/zv8;->OooOo00(F)V

    iget-object v0, v0, Llyiahf/vczjk/d9;->OooOO0O:Llyiahf/vczjk/lr5;

    check-cast v0, Llyiahf/vczjk/zv8;

    invoke-virtual {v0, p2}, Llyiahf/vczjk/zv8;->OooOo00(F)V

    iget-object p2, p0, Llyiahf/vczjk/q7;->$prev:Llyiahf/vczjk/el7;

    iput p1, p2, Llyiahf/vczjk/el7;->element:F

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
