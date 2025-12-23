.class public final synthetic Llyiahf/vczjk/o41;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/xt;


# instance fields
.field public final synthetic OooO00o:Llyiahf/vczjk/r41;

.field public final synthetic OooO0O0:Llyiahf/vczjk/q41;


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/r41;Llyiahf/vczjk/q41;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/o41;->OooO00o:Llyiahf/vczjk/r41;

    iput-object p2, p0, Llyiahf/vczjk/o41;->OooO0O0:Llyiahf/vczjk/q41;

    return-void
.end method


# virtual methods
.method public final OooO00o(Lgithub/tornaco/android/thanos/core/pm/AppInfo;)V
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/o41;->OooO00o:Llyiahf/vczjk/r41;

    iget-boolean v1, v0, Llyiahf/vczjk/r41;->OooO:Z

    iget-object v2, p0, Llyiahf/vczjk/o41;->OooO0O0:Llyiahf/vczjk/q41;

    if-eqz v1, :cond_0

    invoke-virtual {p1}, Lgithub/tornaco/android/thanos/core/pm/AppInfo;->isSelected()Z

    move-result v1

    xor-int/lit8 v1, v1, 0x1

    invoke-virtual {p1, v1}, Lgithub/tornaco/android/thanos/core/pm/AppInfo;->setSelected(Z)V

    iget-object v1, v2, Llyiahf/vczjk/q41;->Oooo00O:Llyiahf/vczjk/z44;

    iget-object v1, v1, Llyiahf/vczjk/z44;->OooOOo0:Lgithub/tornaco/android/thanos/widget/checkable/CheckableImageView;

    invoke-virtual {v1}, Lgithub/tornaco/android/thanos/widget/checkable/CheckableImageView;->toggle()V

    :cond_0
    iget-object v1, v0, Llyiahf/vczjk/r41;->OooO0o:Llyiahf/vczjk/fu;

    if-eqz v1, :cond_1

    iget-object v0, v2, Landroidx/recyclerview/widget/o000oOoO;->OooOOO0:Landroid/view/View;

    invoke-interface {v1, p1, v0}, Llyiahf/vczjk/fu;->OooO00o(Lgithub/tornaco/android/thanos/core/pm/AppInfo;Landroid/view/View;)V

    return-void

    :cond_1
    iget-object v0, v0, Llyiahf/vczjk/r41;->OooO0o0:Llyiahf/vczjk/xt;

    if-eqz v0, :cond_2

    invoke-interface {v0, p1}, Llyiahf/vczjk/xt;->OooO00o(Lgithub/tornaco/android/thanos/core/pm/AppInfo;)V

    :cond_2
    return-void
.end method
