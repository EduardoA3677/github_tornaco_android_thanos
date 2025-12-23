.class public final Llyiahf/vczjk/vb6;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/h43;


# instance fields
.field public final synthetic OooOOO:Landroid/content/Context;

.field public final synthetic OooOOO0:I


# direct methods
.method public synthetic constructor <init>(Landroid/content/Context;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/vb6;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/vb6;->OooOOO:Landroid/content/Context;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final emit(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Ljava/lang/Object;
    .locals 1

    iget p2, p0, Llyiahf/vczjk/vb6;->OooOOO0:I

    packed-switch p2, :pswitch_data_0

    check-cast p1, Llyiahf/vczjk/fr2;

    instance-of p2, p1, Llyiahf/vczjk/cr2;

    iget-object v0, p0, Llyiahf/vczjk/vb6;->OooOOO:Landroid/content/Context;

    if-eqz p2, :cond_0

    invoke-static {v0}, Llyiahf/vczjk/kh6;->Oooo0o(Landroid/content/Context;)V

    goto :goto_0

    :cond_0
    instance-of p2, p1, Llyiahf/vczjk/yq2;

    if-eqz p2, :cond_1

    check-cast p1, Llyiahf/vczjk/yq2;

    iget-object p1, p1, Llyiahf/vczjk/yq2;->OooO00o:Ljava/lang/String;

    invoke-static {v0, p1}, Llyiahf/vczjk/kh6;->Oooo0o0(Landroid/content/Context;Ljava/lang/String;)V

    goto :goto_0

    :cond_1
    instance-of p2, p1, Llyiahf/vczjk/ar2;

    if-eqz p2, :cond_2

    check-cast p1, Llyiahf/vczjk/ar2;

    iget-object p1, p1, Llyiahf/vczjk/ar2;->OooO00o:Ljava/lang/String;

    new-instance p2, Ljava/lang/StringBuilder;

    invoke-direct {p2}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {p2, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string p1, " already exists"

    invoke-virtual {p2, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {p2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    invoke-static {v0, p1}, Llyiahf/vczjk/kh6;->Oooo0o0(Landroid/content/Context;Ljava/lang/String;)V

    :goto_0
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :cond_2
    new-instance p1, Llyiahf/vczjk/k61;

    invoke-direct {p1}, Ljava/lang/RuntimeException;-><init>()V

    throw p1

    :pswitch_0
    check-cast p1, Llyiahf/vczjk/dr2;

    instance-of p2, p1, Llyiahf/vczjk/br2;

    iget-object v0, p0, Llyiahf/vczjk/vb6;->OooOOO:Landroid/content/Context;

    if-eqz p2, :cond_3

    invoke-static {v0}, Llyiahf/vczjk/kh6;->Oooo0o(Landroid/content/Context;)V

    goto :goto_1

    :cond_3
    instance-of p2, p1, Llyiahf/vczjk/xq2;

    if-eqz p2, :cond_4

    check-cast p1, Llyiahf/vczjk/xq2;

    iget-object p1, p1, Llyiahf/vczjk/xq2;->OooO00o:Ljava/lang/String;

    invoke-static {v0, p1}, Llyiahf/vczjk/kh6;->Oooo0o0(Landroid/content/Context;Ljava/lang/String;)V

    goto :goto_1

    :cond_4
    instance-of p2, p1, Llyiahf/vczjk/zq2;

    if-eqz p2, :cond_5

    check-cast p1, Llyiahf/vczjk/zq2;

    iget-object p1, p1, Llyiahf/vczjk/zq2;->OooO00o:Ljava/lang/String;

    new-instance p2, Ljava/lang/StringBuilder;

    invoke-direct {p2}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {p2, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string p1, " already exists"

    invoke-virtual {p2, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {p2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    invoke-static {v0, p1}, Llyiahf/vczjk/kh6;->Oooo0o0(Landroid/content/Context;Ljava/lang/String;)V

    :goto_1
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :cond_5
    new-instance p1, Llyiahf/vczjk/k61;

    invoke-direct {p1}, Ljava/lang/RuntimeException;-><init>()V

    throw p1

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
