.class public final Llyiahf/vczjk/bk7;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/an1;


# instance fields
.field public final synthetic OooO00o:I

.field public final OooO0O0:Ljava/lang/String;

.field public final OooO0OO:Llyiahf/vczjk/ii;

.field public final OooO0Oo:Z

.field public final OooO0o:Ljava/lang/Object;

.field public final OooO0o0:Llyiahf/vczjk/pi;


# direct methods
.method public constructor <init>(Ljava/lang/String;Llyiahf/vczjk/ii;Llyiahf/vczjk/ii;Llyiahf/vczjk/ni;Z)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Llyiahf/vczjk/bk7;->OooO00o:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/bk7;->OooO0O0:Ljava/lang/String;

    iput-object p2, p0, Llyiahf/vczjk/bk7;->OooO0OO:Llyiahf/vczjk/ii;

    iput-object p3, p0, Llyiahf/vczjk/bk7;->OooO0o0:Llyiahf/vczjk/pi;

    iput-object p4, p0, Llyiahf/vczjk/bk7;->OooO0o:Ljava/lang/Object;

    iput-boolean p5, p0, Llyiahf/vczjk/bk7;->OooO0Oo:Z

    return-void
.end method

.method public constructor <init>(Ljava/lang/String;Llyiahf/vczjk/pi;Llyiahf/vczjk/hi;Llyiahf/vczjk/ii;Z)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Llyiahf/vczjk/bk7;->OooO00o:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/bk7;->OooO0O0:Ljava/lang/String;

    iput-object p2, p0, Llyiahf/vczjk/bk7;->OooO0o0:Llyiahf/vczjk/pi;

    iput-object p3, p0, Llyiahf/vczjk/bk7;->OooO0o:Ljava/lang/Object;

    iput-object p4, p0, Llyiahf/vczjk/bk7;->OooO0OO:Llyiahf/vczjk/ii;

    iput-boolean p5, p0, Llyiahf/vczjk/bk7;->OooO0Oo:Z

    return-void
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/v85;Llyiahf/vczjk/z75;Llyiahf/vczjk/f80;)Llyiahf/vczjk/fm1;
    .locals 0

    iget p2, p0, Llyiahf/vczjk/bk7;->OooO00o:I

    packed-switch p2, :pswitch_data_0

    new-instance p2, Llyiahf/vczjk/nq7;

    invoke-direct {p2, p1, p3, p0}, Llyiahf/vczjk/nq7;-><init>(Llyiahf/vczjk/v85;Llyiahf/vczjk/f80;Llyiahf/vczjk/bk7;)V

    return-object p2

    :pswitch_0
    new-instance p2, Llyiahf/vczjk/ak7;

    invoke-direct {p2, p1, p3, p0}, Llyiahf/vczjk/ak7;-><init>(Llyiahf/vczjk/v85;Llyiahf/vczjk/f80;Llyiahf/vczjk/bk7;)V

    return-object p2

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public toString()Ljava/lang/String;
    .locals 2

    iget v0, p0, Llyiahf/vczjk/bk7;->OooO00o:I

    packed-switch v0, :pswitch_data_0

    invoke-super {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0

    :pswitch_0
    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "RectangleShape{position="

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    iget-object v1, p0, Llyiahf/vczjk/bk7;->OooO0o0:Llyiahf/vczjk/pi;

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v1, ", size="

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget-object v1, p0, Llyiahf/vczjk/bk7;->OooO0o:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/hi;

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const/16 v1, 0x7d

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
