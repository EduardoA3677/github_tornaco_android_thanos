.class public final Llyiahf/vczjk/g42;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field final synthetic $container:Landroid/view/ViewGroup;

.field final synthetic $mergedTransition:Ljava/lang/Object;

.field final synthetic this$0:Landroidx/fragment/app/OooOO0O;


# direct methods
.method public constructor <init>(Landroid/view/ViewGroup;Landroidx/fragment/app/OooOO0O;Ljava/lang/Object;)V
    .locals 0

    iput-object p2, p0, Llyiahf/vczjk/g42;->this$0:Landroidx/fragment/app/OooOO0O;

    iput-object p1, p0, Llyiahf/vczjk/g42;->$container:Landroid/view/ViewGroup;

    iput-object p3, p0, Llyiahf/vczjk/g42;->$mergedTransition:Ljava/lang/Object;

    const/4 p1, 0x0

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/g42;->this$0:Landroidx/fragment/app/OooOO0O;

    iget-object v0, v0, Landroidx/fragment/app/OooOO0O;->OooO0o:Llyiahf/vczjk/pd3;

    iget-object v1, p0, Llyiahf/vczjk/g42;->$container:Landroid/view/ViewGroup;

    iget-object v2, p0, Llyiahf/vczjk/g42;->$mergedTransition:Ljava/lang/Object;

    invoke-virtual {v0, v1, v2}, Llyiahf/vczjk/pd3;->OooO0o0(Landroid/view/ViewGroup;Ljava/lang/Object;)V

    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0
.end method
