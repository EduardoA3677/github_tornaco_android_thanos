.class public final Llyiahf/vczjk/q3;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Landroid/widget/AdapterView$OnItemClickListener;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/s3;

.field public final synthetic OooOOO0:Llyiahf/vczjk/v3;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/s3;Llyiahf/vczjk/v3;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/q3;->OooOOO:Llyiahf/vczjk/s3;

    iput-object p2, p0, Llyiahf/vczjk/q3;->OooOOO0:Llyiahf/vczjk/v3;

    return-void
.end method


# virtual methods
.method public final onItemClick(Landroid/widget/AdapterView;Landroid/view/View;IJ)V
    .locals 0

    iget-object p1, p0, Llyiahf/vczjk/q3;->OooOOO:Llyiahf/vczjk/s3;

    iget-object p2, p1, Llyiahf/vczjk/s3;->OooOOo:Landroid/content/DialogInterface$OnClickListener;

    iget-object p4, p0, Llyiahf/vczjk/q3;->OooOOO0:Llyiahf/vczjk/v3;

    iget-object p5, p4, Llyiahf/vczjk/v3;->OooO0O0:Llyiahf/vczjk/x3;

    invoke-interface {p2, p5, p3}, Landroid/content/DialogInterface$OnClickListener;->onClick(Landroid/content/DialogInterface;I)V

    iget-boolean p1, p1, Llyiahf/vczjk/s3;->OooOo0o:Z

    if-nez p1, :cond_0

    iget-object p1, p4, Llyiahf/vczjk/v3;->OooO0O0:Llyiahf/vczjk/x3;

    invoke-virtual {p1}, Llyiahf/vczjk/x3;->dismiss()V

    :cond_0
    return-void
.end method
