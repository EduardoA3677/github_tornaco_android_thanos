.class public final Llyiahf/vczjk/bv0;
.super Ljava/lang/Object;
.source "SourceFile"


# instance fields
.field public OooO00o:Z

.field public OooO0O0:Z

.field public final OooO0OO:Ljava/lang/Object;

.field public final OooO0Oo:Ljava/lang/Object;

.field public OooO0o0:Ljava/lang/Object;


# direct methods
.method public constructor <init>()V
    .locals 1

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    new-instance v0, Ljava/util/HashMap;

    invoke-direct {v0}, Ljava/util/HashMap;-><init>()V

    iput-object v0, p0, Llyiahf/vczjk/bv0;->OooO0OO:Ljava/lang/Object;

    new-instance v0, Ljava/util/HashSet;

    invoke-direct {v0}, Ljava/util/HashSet;-><init>()V

    iput-object v0, p0, Llyiahf/vczjk/bv0;->OooO0Oo:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Landroid/content/Context;Ljava/lang/String;Llyiahf/vczjk/vu7;ZZ)V
    .locals 1

    const-string v0, "context"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "callback"

    invoke-static {p3, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/bv0;->OooO0OO:Ljava/lang/Object;

    iput-object p2, p0, Llyiahf/vczjk/bv0;->OooO0Oo:Ljava/lang/Object;

    iput-object p3, p0, Llyiahf/vczjk/bv0;->OooO0o0:Ljava/lang/Object;

    iput-boolean p4, p0, Llyiahf/vczjk/bv0;->OooO00o:Z

    iput-boolean p5, p0, Llyiahf/vczjk/bv0;->OooO0O0:Z

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/x02;ZLlyiahf/vczjk/ld9;Llyiahf/vczjk/bo;Z)V
    .locals 1

    const-string v0, "containerContext"

    invoke-static {p3, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/bv0;->OooO0OO:Ljava/lang/Object;

    iput-boolean p2, p0, Llyiahf/vczjk/bv0;->OooO00o:Z

    iput-object p3, p0, Llyiahf/vczjk/bv0;->OooO0Oo:Ljava/lang/Object;

    iput-object p4, p0, Llyiahf/vczjk/bv0;->OooO0o0:Ljava/lang/Object;

    iput-boolean p5, p0, Llyiahf/vczjk/bv0;->OooO0O0:Z

    return-void
.end method

.method public static OooO0O0(Ljava/lang/Object;Ljava/util/ArrayList;Llyiahf/vczjk/oo000o;)V
    .locals 1

    invoke-virtual {p1, p0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    invoke-virtual {p2, p0}, Llyiahf/vczjk/oo000o;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p0

    check-cast p0, Ljava/lang/Iterable;

    if-eqz p0, :cond_0

    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object p0

    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    move-result v0

    if-eqz v0, :cond_0

    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v0

    invoke-static {v0, p1, p2}, Llyiahf/vczjk/bv0;->OooO0O0(Ljava/lang/Object;Ljava/util/ArrayList;Llyiahf/vczjk/oo000o;)V

    goto :goto_0

    :cond_0
    return-void
.end method

.method public static OooO0OO(Llyiahf/vczjk/t4a;)Llyiahf/vczjk/y46;
    .locals 4

    const-string v0, "<this>"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    instance-of v1, p0, Llyiahf/vczjk/hs4;

    if-nez v1, :cond_0

    goto/16 :goto_6

    :cond_0
    invoke-interface {p0}, Llyiahf/vczjk/t4a;->getUpperBounds()Ljava/util/List;

    move-result-object p0

    const-string v1, "getUpperBounds(...)"

    invoke-static {p0, v1}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-interface {p0}, Ljava/util/Collection;->isEmpty()Z

    move-result v1

    if-eqz v1, :cond_1

    goto/16 :goto_6

    :cond_1
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v1

    :cond_2
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    move-result v2

    if-eqz v2, :cond_e

    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/yk4;

    invoke-static {v2}, Llyiahf/vczjk/m6a;->Ooooooo(Llyiahf/vczjk/yk4;)Z

    move-result v2

    if-nez v2, :cond_2

    invoke-interface {p0}, Ljava/util/Collection;->isEmpty()Z

    move-result v1

    if-eqz v1, :cond_3

    goto :goto_0

    :cond_3
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v1

    :cond_4
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    move-result v2

    if-eqz v2, :cond_5

    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/yk4;

    invoke-static {v2}, Llyiahf/vczjk/bv0;->OooO0o(Llyiahf/vczjk/yk4;)Llyiahf/vczjk/x46;

    move-result-object v2

    if-eqz v2, :cond_4

    move-object v1, p0

    goto :goto_2

    :cond_5
    :goto_0
    invoke-interface {p0}, Ljava/util/Collection;->isEmpty()Z

    move-result v1

    if-eqz v1, :cond_6

    goto :goto_6

    :cond_6
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v1

    :cond_7
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    move-result v2

    if-eqz v2, :cond_e

    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/yk4;

    invoke-static {v2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v2, Llyiahf/vczjk/uk4;

    invoke-static {v2}, Llyiahf/vczjk/qu6;->OooO0oO(Llyiahf/vczjk/uk4;)Llyiahf/vczjk/uk4;

    move-result-object v2

    if-eqz v2, :cond_7

    new-instance v1, Ljava/util/ArrayList;

    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v2

    :cond_8
    :goto_1
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    if-eqz v3, :cond_9

    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/yk4;

    invoke-static {v3, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v3, Llyiahf/vczjk/uk4;

    invoke-static {v3}, Llyiahf/vczjk/qu6;->OooO0oO(Llyiahf/vczjk/uk4;)Llyiahf/vczjk/uk4;

    move-result-object v3

    if-eqz v3, :cond_8

    invoke-virtual {v1, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_1

    :cond_9
    :goto_2
    invoke-interface {v1}, Ljava/util/Collection;->isEmpty()Z

    move-result v0

    if-eqz v0, :cond_a

    goto :goto_3

    :cond_a
    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :cond_b
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v2

    if-eqz v2, :cond_c

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/yk4;

    invoke-static {v2}, Llyiahf/vczjk/m6a;->o00ooo(Llyiahf/vczjk/yk4;)Z

    move-result v2

    if-nez v2, :cond_b

    sget-object v0, Llyiahf/vczjk/x46;->OooOOOO:Llyiahf/vczjk/x46;

    goto :goto_4

    :cond_c
    :goto_3
    sget-object v0, Llyiahf/vczjk/x46;->OooOOO:Llyiahf/vczjk/x46;

    :goto_4
    new-instance v2, Llyiahf/vczjk/y46;

    if-eq v1, p0, :cond_d

    const/4 p0, 0x1

    goto :goto_5

    :cond_d
    const/4 p0, 0x0

    :goto_5
    invoke-direct {v2, v0, p0}, Llyiahf/vczjk/y46;-><init>(Llyiahf/vczjk/x46;Z)V

    return-object v2

    :cond_e
    :goto_6
    const/4 p0, 0x0

    return-object p0
.end method

.method public static OooO0o(Llyiahf/vczjk/yk4;)Llyiahf/vczjk/x46;
    .locals 1

    const-string v0, "<this>"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {p0}, Llyiahf/vczjk/m6a;->OooOo(Llyiahf/vczjk/yk4;)Llyiahf/vczjk/k23;

    move-result-object v0

    if-eqz v0, :cond_0

    invoke-static {v0}, Llyiahf/vczjk/m6a;->oo0o0Oo(Llyiahf/vczjk/k23;)Llyiahf/vczjk/dp8;

    move-result-object v0

    if-nez v0, :cond_1

    :cond_0
    invoke-static {p0}, Llyiahf/vczjk/m6a;->OooOoO0(Llyiahf/vczjk/yk4;)Llyiahf/vczjk/dp8;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    :cond_1
    invoke-static {v0}, Llyiahf/vczjk/m6a;->o00Ooo(Llyiahf/vczjk/yk4;)Z

    move-result v0

    if-eqz v0, :cond_2

    sget-object p0, Llyiahf/vczjk/x46;->OooOOO:Llyiahf/vczjk/x46;

    return-object p0

    :cond_2
    invoke-static {p0}, Llyiahf/vczjk/m6a;->OooOo(Llyiahf/vczjk/yk4;)Llyiahf/vczjk/k23;

    move-result-object v0

    if-eqz v0, :cond_3

    invoke-static {v0}, Llyiahf/vczjk/m6a;->o0000Oo0(Llyiahf/vczjk/k23;)Llyiahf/vczjk/dp8;

    move-result-object v0

    if-nez v0, :cond_4

    :cond_3
    invoke-static {p0}, Llyiahf/vczjk/m6a;->OooOoO0(Llyiahf/vczjk/yk4;)Llyiahf/vczjk/dp8;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    :cond_4
    invoke-static {v0}, Llyiahf/vczjk/m6a;->o00Ooo(Llyiahf/vczjk/yk4;)Z

    move-result p0

    if-nez p0, :cond_5

    sget-object p0, Llyiahf/vczjk/x46;->OooOOOO:Llyiahf/vczjk/x46;

    return-object p0

    :cond_5
    const/4 p0, 0x0

    return-object p0
.end method

.method public static OooO0o0(Llyiahf/vczjk/dp8;)Llyiahf/vczjk/ic3;
    .locals 2

    sget-object v0, Llyiahf/vczjk/l5a;->OooO00o:Llyiahf/vczjk/rq2;

    invoke-virtual {p0}, Llyiahf/vczjk/uk4;->o000000()Llyiahf/vczjk/n3a;

    move-result-object p0

    invoke-interface {p0}, Llyiahf/vczjk/n3a;->OooO00o()Llyiahf/vczjk/gz0;

    move-result-object p0

    instance-of v0, p0, Llyiahf/vczjk/by0;

    const/4 v1, 0x0

    if-eqz v0, :cond_0

    check-cast p0, Llyiahf/vczjk/by0;

    goto :goto_0

    :cond_0
    move-object p0, v1

    :goto_0
    if-eqz p0, :cond_1

    invoke-static {p0}, Llyiahf/vczjk/n72;->OooO0oO(Llyiahf/vczjk/v02;)Llyiahf/vczjk/ic3;

    move-result-object p0

    return-object p0

    :cond_1
    return-object v1
.end method


# virtual methods
.method public OooO(Llyiahf/vczjk/yk4;)Ljava/util/ArrayList;
    .locals 4

    new-instance v0, Llyiahf/vczjk/o0O00o0;

    iget-object v1, p0, Llyiahf/vczjk/bv0;->OooO0Oo:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/ld9;

    iget-object v2, v1, Llyiahf/vczjk/ld9;->OooOOOo:Ljava/lang/Object;

    invoke-interface {v2}, Llyiahf/vczjk/kp4;->getValue()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/g74;

    iget-object v1, v1, Llyiahf/vczjk/ld9;->OooOOO:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/s64;

    const-string v3, "<this>"

    invoke-static {p1, v3}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    move-object v3, p1

    check-cast v3, Llyiahf/vczjk/uk4;

    invoke-virtual {v3}, Llyiahf/vczjk/uk4;->OooOOo0()Llyiahf/vczjk/ko;

    move-result-object v3

    iget-object v1, v1, Llyiahf/vczjk/s64;->OooOOo0:Llyiahf/vczjk/eo;

    invoke-virtual {v1, v2, v3}, Llyiahf/vczjk/eo;->OooO0O0(Llyiahf/vczjk/g74;Llyiahf/vczjk/ko;)Llyiahf/vczjk/g74;

    move-result-object v1

    const/4 v2, 0x0

    invoke-direct {v0, p1, v1, v2}, Llyiahf/vczjk/o0O00o0;-><init>(Llyiahf/vczjk/yk4;Llyiahf/vczjk/g74;Llyiahf/vczjk/t4a;)V

    new-instance p1, Llyiahf/vczjk/oo000o;

    const/4 v1, 0x3

    invoke-direct {p1, p0, v1}, Llyiahf/vczjk/oo000o;-><init>(Ljava/lang/Object;I)V

    new-instance v1, Ljava/util/ArrayList;

    const/4 v2, 0x1

    invoke-direct {v1, v2}, Ljava/util/ArrayList;-><init>(I)V

    invoke-static {v0, v1, p1}, Llyiahf/vczjk/bv0;->OooO0O0(Ljava/lang/Object;Ljava/util/ArrayList;Llyiahf/vczjk/oo000o;)V

    return-object v1
.end method

.method public OooO00o(Llyiahf/vczjk/zd5;)Z
    .locals 5

    invoke-interface {p1}, Llyiahf/vczjk/zd5;->getId()I

    move-result v0

    iget-object v1, p0, Llyiahf/vczjk/bv0;->OooO0Oo:Ljava/lang/Object;

    check-cast v1, Ljava/util/HashSet;

    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v2

    invoke-virtual {v1, v2}, Ljava/util/HashSet;->contains(Ljava/lang/Object;)Z

    move-result v2

    const/4 v3, 0x0

    if-eqz v2, :cond_0

    return v3

    :cond_0
    iget-object v2, p0, Llyiahf/vczjk/bv0;->OooO0OO:Ljava/lang/Object;

    check-cast v2, Ljava/util/HashMap;

    invoke-virtual {p0}, Llyiahf/vczjk/bv0;->OooO0oO()I

    move-result v4

    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v4

    invoke-virtual {v2, v4}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/zd5;

    if-eqz v2, :cond_1

    invoke-virtual {p0, v2, v3}, Llyiahf/vczjk/bv0;->OooOO0(Llyiahf/vczjk/zd5;Z)Z

    :cond_1
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v0

    invoke-virtual {v1, v0}, Ljava/util/HashSet;->add(Ljava/lang/Object;)Z

    move-result v0

    invoke-interface {p1}, Landroid/widget/Checkable;->isChecked()Z

    move-result v1

    if-nez v1, :cond_2

    const/4 v1, 0x1

    invoke-interface {p1, v1}, Landroid/widget/Checkable;->setChecked(Z)V

    :cond_2
    return v0
.end method

.method public OooO0Oo(Landroid/view/ViewGroup;)Ljava/util/ArrayList;
    .locals 5

    new-instance v0, Ljava/util/HashSet;

    iget-object v1, p0, Llyiahf/vczjk/bv0;->OooO0Oo:Ljava/lang/Object;

    check-cast v1, Ljava/util/HashSet;

    invoke-direct {v0, v1}, Ljava/util/HashSet;-><init>(Ljava/util/Collection;)V

    new-instance v1, Ljava/util/ArrayList;

    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    const/4 v2, 0x0

    :goto_0
    invoke-virtual {p1}, Landroid/view/ViewGroup;->getChildCount()I

    move-result v3

    if-ge v2, v3, :cond_1

    invoke-virtual {p1, v2}, Landroid/view/ViewGroup;->getChildAt(I)Landroid/view/View;

    move-result-object v3

    instance-of v4, v3, Llyiahf/vczjk/zd5;

    if-eqz v4, :cond_0

    invoke-virtual {v3}, Landroid/view/View;->getId()I

    move-result v4

    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v4

    invoke-virtual {v0, v4}, Ljava/util/HashSet;->contains(Ljava/lang/Object;)Z

    move-result v4

    if-eqz v4, :cond_0

    invoke-virtual {v3}, Landroid/view/View;->getId()I

    move-result v3

    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v3

    invoke-virtual {v1, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    :cond_0
    add-int/lit8 v2, v2, 0x1

    goto :goto_0

    :cond_1
    return-object v1
.end method

.method public OooO0oO()I
    .locals 2

    iget-boolean v0, p0, Llyiahf/vczjk/bv0;->OooO00o:Z

    if-eqz v0, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/bv0;->OooO0Oo:Ljava/lang/Object;

    check-cast v0, Ljava/util/HashSet;

    invoke-virtual {v0}, Ljava/util/HashSet;->isEmpty()Z

    move-result v1

    if-nez v1, :cond_0

    invoke-virtual {v0}, Ljava/util/HashSet;->iterator()Ljava/util/Iterator;

    move-result-object v0

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/lang/Integer;

    invoke-virtual {v0}, Ljava/lang/Integer;->intValue()I

    move-result v0

    return v0

    :cond_0
    const/4 v0, -0x1

    return v0
.end method

.method public OooO0oo()V
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/bv0;->OooO0o0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/uz5;

    if-eqz v0, :cond_1

    new-instance v1, Ljava/util/HashSet;

    iget-object v2, p0, Llyiahf/vczjk/bv0;->OooO0Oo:Ljava/lang/Object;

    check-cast v2, Ljava/util/HashSet;

    invoke-direct {v1, v2}, Ljava/util/HashSet;-><init>(Ljava/util/Collection;)V

    iget-object v0, v0, Llyiahf/vczjk/uz5;->OooOOO:Ljava/lang/Object;

    check-cast v0, Lcom/google/android/material/chip/ChipGroup;

    iget-object v1, v0, Lcom/google/android/material/chip/ChipGroup;->OooOOoo:Llyiahf/vczjk/dw0;

    if-eqz v1, :cond_1

    iget-object v2, v0, Lcom/google/android/material/chip/ChipGroup;->OooOo00:Llyiahf/vczjk/bv0;

    invoke-virtual {v2, v0}, Llyiahf/vczjk/bv0;->OooO0Oo(Landroid/view/ViewGroup;)Ljava/util/ArrayList;

    check-cast v1, Llyiahf/vczjk/vz5;

    iget-object v0, v1, Llyiahf/vczjk/vz5;->OooOOO:Ljava/lang/Object;

    check-cast v0, Lcom/google/android/material/chip/ChipGroup;

    iget-object v1, v0, Lcom/google/android/material/chip/ChipGroup;->OooOo00:Llyiahf/vczjk/bv0;

    iget-boolean v1, v1, Llyiahf/vczjk/bv0;->OooO00o:Z

    if-nez v1, :cond_0

    goto :goto_0

    :cond_0
    invoke-virtual {v0}, Lcom/google/android/material/chip/ChipGroup;->getCheckedChipId()I

    const/4 v0, 0x0

    throw v0

    :cond_1
    :goto_0
    return-void
.end method

.method public OooOO0(Llyiahf/vczjk/zd5;Z)Z
    .locals 4

    invoke-interface {p1}, Llyiahf/vczjk/zd5;->getId()I

    move-result v0

    iget-object v1, p0, Llyiahf/vczjk/bv0;->OooO0Oo:Ljava/lang/Object;

    check-cast v1, Ljava/util/HashSet;

    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v2

    invoke-virtual {v1, v2}, Ljava/util/HashSet;->contains(Ljava/lang/Object;)Z

    move-result v2

    const/4 v3, 0x0

    if-nez v2, :cond_0

    return v3

    :cond_0
    if-eqz p2, :cond_1

    invoke-virtual {v1}, Ljava/util/HashSet;->size()I

    move-result p2

    const/4 v2, 0x1

    if-ne p2, v2, :cond_1

    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object p2

    invoke-virtual {v1, p2}, Ljava/util/HashSet;->contains(Ljava/lang/Object;)Z

    move-result p2

    if-eqz p2, :cond_1

    invoke-interface {p1, v2}, Landroid/widget/Checkable;->setChecked(Z)V

    return v3

    :cond_1
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object p2

    invoke-virtual {v1, p2}, Ljava/util/HashSet;->remove(Ljava/lang/Object;)Z

    move-result p2

    invoke-interface {p1}, Landroid/widget/Checkable;->isChecked()Z

    move-result v0

    if-eqz v0, :cond_2

    invoke-interface {p1, v3}, Landroid/widget/Checkable;->setChecked(Z)V

    :cond_2
    return p2
.end method
