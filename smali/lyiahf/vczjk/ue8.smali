.class public final Llyiahf/vczjk/ue8;
.super Ljava/lang/Object;
.source "SourceFile"


# instance fields
.field public final OooO00o:Llyiahf/vczjk/ro4;

.field public final OooO0O0:Llyiahf/vczjk/en2;

.field public final OooO0OO:Llyiahf/vczjk/or5;

.field public final OooO0Oo:Llyiahf/vczjk/as5;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/ro4;Llyiahf/vczjk/en2;Llyiahf/vczjk/or5;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/ue8;->OooO00o:Llyiahf/vczjk/ro4;

    iput-object p2, p0, Llyiahf/vczjk/ue8;->OooO0O0:Llyiahf/vczjk/en2;

    iput-object p3, p0, Llyiahf/vczjk/ue8;->OooO0OO:Llyiahf/vczjk/or5;

    new-instance p1, Llyiahf/vczjk/as5;

    const/4 p2, 0x2

    invoke-direct {p1, p2}, Llyiahf/vczjk/as5;-><init>(I)V

    iput-object p1, p0, Llyiahf/vczjk/ue8;->OooO0Oo:Llyiahf/vczjk/as5;

    return-void
.end method


# virtual methods
.method public final OooO00o()Llyiahf/vczjk/re8;
    .locals 5

    new-instance v0, Llyiahf/vczjk/je8;

    invoke-direct {v0}, Llyiahf/vczjk/je8;-><init>()V

    new-instance v1, Llyiahf/vczjk/re8;

    const/4 v2, 0x0

    iget-object v3, p0, Llyiahf/vczjk/ue8;->OooO0O0:Llyiahf/vczjk/en2;

    iget-object v4, p0, Llyiahf/vczjk/ue8;->OooO00o:Llyiahf/vczjk/ro4;

    invoke-direct {v1, v3, v2, v4, v0}, Llyiahf/vczjk/re8;-><init>(Llyiahf/vczjk/jl5;ZLlyiahf/vczjk/ro4;Llyiahf/vczjk/je8;)V

    return-object v1
.end method

.method public final OooO0O0(Llyiahf/vczjk/ro4;Llyiahf/vczjk/je8;)V
    .locals 13

    iget-object v0, p0, Llyiahf/vczjk/ue8;->OooO0Oo:Llyiahf/vczjk/as5;

    iget-object v1, v0, Llyiahf/vczjk/c76;->OooO00o:[Ljava/lang/Object;

    iget v0, v0, Llyiahf/vczjk/c76;->OooO0O0:I

    const/4 v2, 0x0

    move v3, v2

    :goto_0
    if-ge v3, v0, :cond_b

    aget-object v4, v1, v3

    check-cast v4, Llyiahf/vczjk/q9;

    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-virtual {p1}, Llyiahf/vczjk/ro4;->OooOo()Llyiahf/vczjk/je8;

    move-result-object v5

    iget v6, p1, Llyiahf/vczjk/ro4;->OooOOO:I

    const/4 v7, 0x0

    if-eqz p2, :cond_1

    sget-object v8, Llyiahf/vczjk/ve8;->OooOoo:Llyiahf/vczjk/ze8;

    iget-object v9, p2, Llyiahf/vczjk/je8;->OooOOO0:Llyiahf/vczjk/js5;

    invoke-virtual {v9, v8}, Llyiahf/vczjk/js5;->OooO0oO(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v8

    if-nez v8, :cond_0

    move-object v8, v7

    :cond_0
    check-cast v8, Llyiahf/vczjk/an;

    if-eqz v8, :cond_1

    iget-object v8, v8, Llyiahf/vczjk/an;->OooOOO:Ljava/lang/String;

    goto :goto_1

    :cond_1
    move-object v8, v7

    :goto_1
    if-eqz v5, :cond_3

    sget-object v9, Llyiahf/vczjk/ve8;->OooOoo:Llyiahf/vczjk/ze8;

    iget-object v10, v5, Llyiahf/vczjk/je8;->OooOOO0:Llyiahf/vczjk/js5;

    invoke-virtual {v10, v9}, Llyiahf/vczjk/js5;->OooO0oO(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v9

    if-nez v9, :cond_2

    move-object v9, v7

    :cond_2
    check-cast v9, Llyiahf/vczjk/an;

    if-eqz v9, :cond_3

    iget-object v7, v9, Llyiahf/vczjk/an;->OooOOO:Ljava/lang/String;

    :cond_3
    const/4 v9, 0x1

    if-eq v8, v7, :cond_6

    iget-object v10, v4, Llyiahf/vczjk/q9;->OooO0OO:Llyiahf/vczjk/xa;

    iget-object v11, v4, Llyiahf/vczjk/q9;->OooO00o:Llyiahf/vczjk/oO0OOo0o;

    if-nez v8, :cond_4

    invoke-virtual {v11, v10, v6, v9}, Llyiahf/vczjk/oO0OOo0o;->Oooo0(Landroid/view/View;IZ)V

    goto :goto_2

    :cond_4
    if-nez v7, :cond_5

    invoke-virtual {v11, v10, v6, v2}, Llyiahf/vczjk/oO0OOo0o;->Oooo0(Landroid/view/View;IZ)V

    goto :goto_2

    :cond_5
    sget-object v8, Llyiahf/vczjk/ve8;->OooOOo0:Llyiahf/vczjk/ze8;

    invoke-static {v5, v8}, Llyiahf/vczjk/dl6;->OooO0oO(Llyiahf/vczjk/je8;Llyiahf/vczjk/ze8;)Ljava/lang/Object;

    move-result-object v8

    check-cast v8, Llyiahf/vczjk/hc;

    sget-object v12, Llyiahf/vczjk/tp3;->OooOOOO:Llyiahf/vczjk/hc;

    invoke-static {v8, v12}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v8

    if-eqz v8, :cond_6

    invoke-virtual {v7}, Ljava/lang/String;->toString()Ljava/lang/String;

    move-result-object v7

    invoke-static {v7}, Llyiahf/vczjk/cr;->OooO0oO(Ljava/lang/String;)Landroid/view/autofill/AutofillValue;

    move-result-object v7

    iget-object v8, v11, Llyiahf/vczjk/oO0OOo0o;->OooOOO:Ljava/lang/Object;

    check-cast v8, Landroid/view/autofill/AutofillManager;

    invoke-static {v8, v10, v6, v7}, Llyiahf/vczjk/bx6;->OooOOoo(Landroid/view/autofill/AutofillManager;Llyiahf/vczjk/xa;ILandroid/view/autofill/AutofillValue;)V

    :cond_6
    :goto_2
    if-eqz p2, :cond_7

    sget-object v7, Llyiahf/vczjk/ve8;->OooOOOo:Llyiahf/vczjk/ze8;

    iget-object v8, p2, Llyiahf/vczjk/je8;->OooOOO0:Llyiahf/vczjk/js5;

    invoke-virtual {v8, v7}, Llyiahf/vczjk/js5;->OooO0O0(Ljava/lang/Object;)Z

    move-result v7

    if-ne v7, v9, :cond_7

    move v7, v9

    goto :goto_3

    :cond_7
    move v7, v2

    :goto_3
    if-eqz v5, :cond_8

    sget-object v8, Llyiahf/vczjk/ve8;->OooOOOo:Llyiahf/vczjk/ze8;

    iget-object v5, v5, Llyiahf/vczjk/je8;->OooOOO0:Llyiahf/vczjk/js5;

    invoke-virtual {v5, v8}, Llyiahf/vczjk/js5;->OooO0O0(Ljava/lang/Object;)Z

    move-result v5

    if-ne v5, v9, :cond_8

    goto :goto_4

    :cond_8
    move v9, v2

    :goto_4
    if-eq v7, v9, :cond_a

    iget-object v4, v4, Llyiahf/vczjk/q9;->OooO0oo:Llyiahf/vczjk/pr5;

    if-eqz v9, :cond_9

    invoke-virtual {v4, v6}, Llyiahf/vczjk/pr5;->OooO00o(I)Z

    goto :goto_5

    :cond_9
    invoke-virtual {v4, v6}, Llyiahf/vczjk/pr5;->OooO0o0(I)Z

    :cond_a
    :goto_5
    add-int/lit8 v3, v3, 0x1

    goto/16 :goto_0

    :cond_b
    return-void
.end method
