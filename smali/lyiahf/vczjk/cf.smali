.class public final Llyiahf/vczjk/cf;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $layoutDirection:Llyiahf/vczjk/yn4;

.field final synthetic $onDismissRequest:Llyiahf/vczjk/le3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/le3;"
        }
    .end annotation
.end field

.field final synthetic $popupLayout:Llyiahf/vczjk/zz6;

.field final synthetic $properties:Llyiahf/vczjk/d07;

.field final synthetic $testTag:Ljava/lang/String;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/zz6;Llyiahf/vczjk/le3;Llyiahf/vczjk/d07;Ljava/lang/String;Llyiahf/vczjk/yn4;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/cf;->$popupLayout:Llyiahf/vczjk/zz6;

    iput-object p2, p0, Llyiahf/vczjk/cf;->$onDismissRequest:Llyiahf/vczjk/le3;

    iput-object p3, p0, Llyiahf/vczjk/cf;->$properties:Llyiahf/vczjk/d07;

    iput-object p4, p0, Llyiahf/vczjk/cf;->$testTag:Ljava/lang/String;

    iput-object p5, p0, Llyiahf/vczjk/cf;->$layoutDirection:Llyiahf/vczjk/yn4;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

    check-cast p1, Llyiahf/vczjk/qc2;

    iget-object p1, p0, Llyiahf/vczjk/cf;->$popupLayout:Llyiahf/vczjk/zz6;

    iget-object v0, p1, Llyiahf/vczjk/zz6;->OooOoOO:Landroid/view/WindowManager$LayoutParams;

    iget-object v1, p1, Llyiahf/vczjk/zz6;->OooOoO:Landroid/view/WindowManager;

    invoke-interface {v1, p1, v0}, Landroid/view/ViewManager;->addView(Landroid/view/View;Landroid/view/ViewGroup$LayoutParams;)V

    iget-object p1, p0, Llyiahf/vczjk/cf;->$popupLayout:Llyiahf/vczjk/zz6;

    iget-object v0, p0, Llyiahf/vczjk/cf;->$onDismissRequest:Llyiahf/vczjk/le3;

    iget-object v1, p0, Llyiahf/vczjk/cf;->$properties:Llyiahf/vczjk/d07;

    iget-object v2, p0, Llyiahf/vczjk/cf;->$testTag:Ljava/lang/String;

    iget-object v3, p0, Llyiahf/vczjk/cf;->$layoutDirection:Llyiahf/vczjk/yn4;

    invoke-virtual {p1, v0, v1, v2, v3}, Llyiahf/vczjk/zz6;->OooOO0O(Llyiahf/vczjk/le3;Llyiahf/vczjk/d07;Ljava/lang/String;Llyiahf/vczjk/yn4;)V

    iget-object p1, p0, Llyiahf/vczjk/cf;->$popupLayout:Llyiahf/vczjk/zz6;

    new-instance v0, Llyiahf/vczjk/x;

    const/4 v1, 0x3

    invoke-direct {v0, p1, v1}, Llyiahf/vczjk/x;-><init>(Ljava/lang/Object;I)V

    return-object v0
.end method
