.class public final Llyiahf/vczjk/t53;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/f43;


# instance fields
.field public final synthetic OooOOO:I

.field public final synthetic OooOOO0:I

.field public final synthetic OooOOOO:Llyiahf/vczjk/f43;


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/f43;II)V
    .locals 0

    iput p3, p0, Llyiahf/vczjk/t53;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/t53;->OooOOOO:Llyiahf/vczjk/f43;

    iput p2, p0, Llyiahf/vczjk/t53;->OooOOO:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/h43;Llyiahf/vczjk/yo1;)Ljava/lang/Object;
    .locals 3

    iget v0, p0, Llyiahf/vczjk/t53;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    new-instance v0, Llyiahf/vczjk/zi6;

    iget v1, p0, Llyiahf/vczjk/t53;->OooOOO:I

    invoke-direct {v0, p1, v1}, Llyiahf/vczjk/zi6;-><init>(Llyiahf/vczjk/h43;I)V

    iget-object p1, p0, Llyiahf/vczjk/t53;->OooOOOO:Llyiahf/vczjk/f43;

    check-cast p1, Llyiahf/vczjk/t53;

    invoke-virtual {p1, v0, p2}, Llyiahf/vczjk/t53;->OooO00o(Llyiahf/vczjk/h43;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    sget-object p2, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    if-ne p1, p2, :cond_0

    goto :goto_0

    :cond_0
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    :goto_0
    return-object p1

    :pswitch_0
    new-instance v0, Llyiahf/vczjk/fl7;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    new-instance v1, Llyiahf/vczjk/v53;

    iget v2, p0, Llyiahf/vczjk/t53;->OooOOO:I

    invoke-direct {v1, v0, v2, p1}, Llyiahf/vczjk/v53;-><init>(Llyiahf/vczjk/fl7;ILlyiahf/vczjk/h43;)V

    iget-object p1, p0, Llyiahf/vczjk/t53;->OooOOOO:Llyiahf/vczjk/f43;

    invoke-interface {p1, v1, p2}, Llyiahf/vczjk/f43;->OooO00o(Llyiahf/vczjk/h43;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    sget-object p2, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    if-ne p1, p2, :cond_1

    goto :goto_1

    :cond_1
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    :goto_1
    return-object p1

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
