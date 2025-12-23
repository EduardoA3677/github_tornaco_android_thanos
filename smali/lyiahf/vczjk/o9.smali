.class public final Llyiahf/vczjk/o9;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/df3;


# instance fields
.field final synthetic $semanticsId:I

.field final synthetic this$0:Llyiahf/vczjk/q9;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/q9;I)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/o9;->this$0:Llyiahf/vczjk/q9;

    iput p2, p0, Llyiahf/vczjk/o9;->$semanticsId:I

    const/4 p1, 0x4

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

    check-cast p1, Ljava/lang/Number;

    invoke-virtual {p1}, Ljava/lang/Number;->intValue()I

    move-result p1

    check-cast p2, Ljava/lang/Number;

    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    move-result p2

    check-cast p3, Ljava/lang/Number;

    invoke-virtual {p3}, Ljava/lang/Number;->intValue()I

    move-result p3

    check-cast p4, Ljava/lang/Number;

    invoke-virtual {p4}, Ljava/lang/Number;->intValue()I

    move-result p4

    iget-object v0, p0, Llyiahf/vczjk/o9;->this$0:Llyiahf/vczjk/q9;

    iget-object v1, v0, Llyiahf/vczjk/q9;->OooO00o:Llyiahf/vczjk/oO0OOo0o;

    iget v2, p0, Llyiahf/vczjk/o9;->$semanticsId:I

    new-instance v3, Landroid/graphics/Rect;

    invoke-direct {v3, p1, p2, p3, p4}, Landroid/graphics/Rect;-><init>(IIII)V

    iget-object p1, v0, Llyiahf/vczjk/q9;->OooO0OO:Llyiahf/vczjk/xa;

    iget-object p2, v1, Llyiahf/vczjk/oO0OOo0o;->OooOOO:Ljava/lang/Object;

    check-cast p2, Landroid/view/autofill/AutofillManager;

    invoke-static {p2, p1, v2, v3}, Llyiahf/vczjk/bx6;->OooOOo(Landroid/view/autofill/AutofillManager;Llyiahf/vczjk/xa;ILandroid/graphics/Rect;)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
