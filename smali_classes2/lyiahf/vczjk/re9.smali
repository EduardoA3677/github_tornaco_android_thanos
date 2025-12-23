.class public final Llyiahf/vczjk/re9;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/cd5;


# instance fields
.field public final synthetic OooO00o:I

.field public final synthetic OooO0O0:Llyiahf/vczjk/jf0;


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/jf0;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/re9;->OooO00o:I

    iput-object p1, p0, Llyiahf/vczjk/re9;->OooO0O0:Llyiahf/vczjk/jf0;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/ld9;Llyiahf/vczjk/ak1;)V
    .locals 12

    iget v0, p0, Llyiahf/vczjk/re9;->OooO00o:I

    packed-switch v0, :pswitch_data_0

    check-cast p2, Llyiahf/vczjk/je9;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/ld9;->Ooooooo(Llyiahf/vczjk/ak1;)V

    iget-object p1, p0, Llyiahf/vczjk/re9;->OooO0O0:Llyiahf/vczjk/jf0;

    const/4 p2, 0x0

    iput p2, p1, Llyiahf/vczjk/jf0;->OooO0O0:I

    return-void

    :pswitch_0
    check-cast p2, Llyiahf/vczjk/se9;

    iget-object v0, p0, Llyiahf/vczjk/re9;->OooO0O0:Llyiahf/vczjk/jf0;

    invoke-static {v0, p1, p2}, Llyiahf/vczjk/jf0;->OooO00o(Llyiahf/vczjk/jf0;Llyiahf/vczjk/ld9;Llyiahf/vczjk/vu1;)V

    return-void

    :pswitch_1
    check-cast p2, Llyiahf/vczjk/me9;

    iget-object v0, p0, Llyiahf/vczjk/re9;->OooO0O0:Llyiahf/vczjk/jf0;

    invoke-static {v0, p1, p2}, Llyiahf/vczjk/jf0;->OooO00o(Llyiahf/vczjk/jf0;Llyiahf/vczjk/ld9;Llyiahf/vczjk/vu1;)V

    return-void

    :pswitch_2
    check-cast p2, Llyiahf/vczjk/le9;

    invoke-virtual {p1}, Llyiahf/vczjk/ld9;->OoooOoo()I

    move-result v0

    invoke-virtual {p1, p2}, Llyiahf/vczjk/ld9;->Ooooooo(Llyiahf/vczjk/ak1;)V

    iget-object v1, p0, Llyiahf/vczjk/re9;->OooO0O0:Llyiahf/vczjk/jf0;

    iget-object v2, v1, Llyiahf/vczjk/jf0;->OooO0o0:Ljava/lang/Object;

    check-cast v2, Ljava/util/ArrayList;

    const/4 v3, 0x2

    if-nez v2, :cond_0

    new-instance v2, Ljava/util/ArrayList;

    invoke-direct {v2, v3}, Ljava/util/ArrayList;-><init>(I)V

    iput-object v2, v1, Llyiahf/vczjk/jf0;->OooO0o0:Ljava/lang/Object;

    :cond_0
    iget-object v2, v1, Llyiahf/vczjk/jf0;->OooO0o0:Ljava/lang/Object;

    check-cast v2, Ljava/util/ArrayList;

    new-instance v4, Llyiahf/vczjk/ue9;

    iget-object v5, p2, Llyiahf/vczjk/le9;->OooO0oo:Llyiahf/vczjk/ke9;

    if-eqz v5, :cond_2

    invoke-virtual {v5}, Ljava/lang/Enum;->ordinal()I

    move-result v5

    const/4 v6, 0x1

    if-eq v5, v6, :cond_1

    if-eq v5, v3, :cond_3

    goto :goto_0

    :cond_1
    move v3, v6

    goto :goto_1

    :cond_2
    :goto_0
    const/4 v3, 0x0

    :cond_3
    :goto_1
    iget-object p1, p1, Llyiahf/vczjk/ld9;->OooOOOo:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/iy8;

    iget-object v5, p1, Llyiahf/vczjk/iy8;->OooOOO0:Ljava/lang/StringBuilder;

    invoke-virtual {v5}, Ljava/lang/StringBuilder;->length()I

    move-result v6

    new-instance v7, Llyiahf/vczjk/gy8;

    invoke-virtual {v5, v0, v6}, Ljava/lang/StringBuilder;->subSequence(II)Ljava/lang/CharSequence;

    move-result-object v8

    invoke-direct {v7, v8}, Landroid/text/SpannableStringBuilder;-><init>(Ljava/lang/CharSequence;)V

    iget-object p1, p1, Llyiahf/vczjk/iy8;->OooOOO:Ljava/util/ArrayDeque;

    invoke-virtual {p1}, Ljava/util/ArrayDeque;->iterator()Ljava/util/Iterator;

    move-result-object p1

    :cond_4
    :goto_2
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    move-result v8

    if-eqz v8, :cond_5

    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v8

    check-cast v8, Llyiahf/vczjk/fy8;

    if-eqz v8, :cond_5

    iget v9, v8, Llyiahf/vczjk/fy8;->OooO0O0:I

    if-lt v9, v0, :cond_4

    iget v10, v8, Llyiahf/vczjk/fy8;->OooO0OO:I

    if-gt v10, v6, :cond_4

    sub-int/2addr v9, v0

    sub-int/2addr v10, v0

    const/16 v11, 0x21

    iget-object v8, v8, Llyiahf/vczjk/fy8;->OooO00o:Ljava/lang/Object;

    invoke-virtual {v7, v8, v9, v10, v11}, Landroid/text/SpannableStringBuilder;->setSpan(Ljava/lang/Object;III)V

    invoke-interface {p1}, Ljava/util/Iterator;->remove()V

    goto :goto_2

    :cond_5
    const-string p1, ""

    invoke-virtual {v5, v0, v6, p1}, Ljava/lang/StringBuilder;->replace(IILjava/lang/String;)Ljava/lang/StringBuilder;

    invoke-direct {v4, v3, v7}, Llyiahf/vczjk/ue9;-><init>(ILlyiahf/vczjk/gy8;)V

    invoke-virtual {v2, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    iget-boolean p1, p2, Llyiahf/vczjk/le9;->OooO0oO:Z

    iput-boolean p1, v1, Llyiahf/vczjk/jf0;->OooO0OO:Z

    return-void

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
