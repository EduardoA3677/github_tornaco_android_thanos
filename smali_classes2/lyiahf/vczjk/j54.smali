.class public final Llyiahf/vczjk/j54;
.super Landroidx/recyclerview/widget/o000oOoO;
.source "SourceFile"


# static fields
.field public static final synthetic Oooo00o:I


# instance fields
.field public final Oooo00O:Llyiahf/vczjk/gm5;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/gm5;)V
    .locals 1

    invoke-virtual {p1}, Landroidx/databinding/ViewDataBinding;->getRoot()Landroid/view/View;

    move-result-object v0

    invoke-direct {p0, v0}, Landroidx/recyclerview/widget/o000oOoO;-><init>(Landroid/view/View;)V

    iput-object p1, p0, Llyiahf/vczjk/j54;->Oooo00O:Llyiahf/vczjk/gm5;

    return-void
.end method


# virtual methods
.method public final OooOOo0(Llyiahf/vczjk/w36;)V
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/j54;->Oooo00O:Llyiahf/vczjk/gm5;

    if-nez p1, :cond_0

    iget-object p1, v0, Llyiahf/vczjk/gm5;->OooOOOO:Landroidx/cardview/widget/CardView;

    const/4 v0, 0x4

    invoke-virtual {p1, v0}, Landroid/view/View;->setVisibility(I)V

    return-void

    :cond_0
    iget-object v1, p1, Llyiahf/vczjk/w36;->OooO0Oo:Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    invoke-virtual {v0, v1}, Llyiahf/vczjk/gm5;->OooO0o0(Lgithub/tornaco/android/thanos/core/pm/AppInfo;)V

    iget-object v1, p1, Llyiahf/vczjk/w36;->OooO0OO:Lgithub/tornaco/android/thanos/core/n/NotificationRecord;

    invoke-virtual {v0, v1}, Llyiahf/vczjk/gm5;->OooO0o(Lgithub/tornaco/android/thanos/core/n/NotificationRecord;)V

    iget-object v1, p1, Llyiahf/vczjk/y36;->OooO0O0:Ljava/lang/String;

    invoke-virtual {v0, v1}, Llyiahf/vczjk/gm5;->OooO(Ljava/lang/String;)V

    new-instance v1, Llyiahf/vczjk/c6;

    const/4 v2, 0x2

    invoke-direct {v1, v2, p0, p1}, Llyiahf/vczjk/c6;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    iget-object p1, v0, Llyiahf/vczjk/gm5;->OooOOOO:Landroidx/cardview/widget/CardView;

    invoke-virtual {p1, v1}, Landroid/view/View;->setOnClickListener(Landroid/view/View$OnClickListener;)V

    invoke-virtual {v0}, Landroidx/databinding/ViewDataBinding;->executePendingBindings()V

    return-void
.end method
