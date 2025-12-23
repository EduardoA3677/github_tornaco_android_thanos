.class public final synthetic Llyiahf/vczjk/mb8;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/bja;
.implements Llyiahf/vczjk/u96;


# instance fields
.field public final synthetic OooOOO0:Lcom/google/android/material/search/SearchView;


# direct methods
.method public synthetic constructor <init>(Lcom/google/android/material/search/SearchView;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/mb8;->OooOOO0:Lcom/google/android/material/search/SearchView;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public OooOOOO(Landroid/view/View;Llyiahf/vczjk/ioa;Llyiahf/vczjk/cja;)Llyiahf/vczjk/ioa;
    .locals 4

    iget-object p1, p0, Llyiahf/vczjk/mb8;->OooOOO0:Lcom/google/android/material/search/SearchView;

    iget-object p1, p1, Lcom/google/android/material/search/SearchView;->OooOOoo:Lcom/google/android/material/appbar/MaterialToolbar;

    invoke-static {p1}, Llyiahf/vczjk/ls6;->OooOO0o(Landroid/view/View;)Z

    move-result v0

    if-eqz v0, :cond_0

    iget v1, p3, Llyiahf/vczjk/cja;->OooO0OO:I

    goto :goto_0

    :cond_0
    iget v1, p3, Llyiahf/vczjk/cja;->OooO00o:I

    :goto_0
    if-eqz v0, :cond_1

    iget v0, p3, Llyiahf/vczjk/cja;->OooO00o:I

    goto :goto_1

    :cond_1
    iget v0, p3, Llyiahf/vczjk/cja;->OooO0OO:I

    :goto_1
    iget-object v2, p2, Llyiahf/vczjk/ioa;->OooO00o:Llyiahf/vczjk/foa;

    const/16 v3, 0x287

    invoke-virtual {v2, v3}, Llyiahf/vczjk/foa;->OooO0oO(I)Llyiahf/vczjk/x04;

    move-result-object v2

    iget v3, v2, Llyiahf/vczjk/x04;->OooO00o:I

    add-int/2addr v1, v3

    iget v2, v2, Llyiahf/vczjk/x04;->OooO0OO:I

    add-int/2addr v0, v2

    iget v2, p3, Llyiahf/vczjk/cja;->OooO0O0:I

    iget p3, p3, Llyiahf/vczjk/cja;->OooO0Oo:I

    invoke-virtual {p1, v1, v2, v0, p3}, Landroid/view/View;->setPadding(IIII)V

    return-object p2
.end method

.method public Oooo0oO(Landroid/view/View;Llyiahf/vczjk/ioa;)Llyiahf/vczjk/ioa;
    .locals 0

    iget-object p1, p0, Llyiahf/vczjk/mb8;->OooOOO0:Lcom/google/android/material/search/SearchView;

    invoke-static {p1, p2}, Lcom/google/android/material/search/SearchView;->OooO0o0(Lcom/google/android/material/search/SearchView;Llyiahf/vczjk/ioa;)V

    return-object p2
.end method
