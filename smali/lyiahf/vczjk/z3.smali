.class public final synthetic Llyiahf/vczjk/z3;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/kl5;

.field public final synthetic OooOOO0:I

.field public final synthetic OooOOOO:Llyiahf/vczjk/le3;

.field public final synthetic OooOOOo:I

.field public final synthetic OooOOo:Ljava/lang/Object;

.field public final synthetic OooOOo0:I

.field public final synthetic OooOOoo:Llyiahf/vczjk/ze3;


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/kl5;Ljava/lang/String;Llyiahf/vczjk/ze3;Llyiahf/vczjk/le3;II)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Llyiahf/vczjk/z3;->OooOOO0:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/z3;->OooOOO:Llyiahf/vczjk/kl5;

    iput-object p2, p0, Llyiahf/vczjk/z3;->OooOOo:Ljava/lang/Object;

    iput-object p3, p0, Llyiahf/vczjk/z3;->OooOOoo:Llyiahf/vczjk/ze3;

    iput-object p4, p0, Llyiahf/vczjk/z3;->OooOOOO:Llyiahf/vczjk/le3;

    iput p5, p0, Llyiahf/vczjk/z3;->OooOOOo:I

    iput p6, p0, Llyiahf/vczjk/z3;->OooOOo0:I

    return-void
.end method

.method public synthetic constructor <init>(Llyiahf/vczjk/le3;Llyiahf/vczjk/kl5;Llyiahf/vczjk/ab2;Llyiahf/vczjk/a91;II)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Llyiahf/vczjk/z3;->OooOOO0:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/z3;->OooOOOO:Llyiahf/vczjk/le3;

    iput-object p2, p0, Llyiahf/vczjk/z3;->OooOOO:Llyiahf/vczjk/kl5;

    iput-object p3, p0, Llyiahf/vczjk/z3;->OooOOo:Ljava/lang/Object;

    iput-object p4, p0, Llyiahf/vczjk/z3;->OooOOoo:Llyiahf/vczjk/ze3;

    iput p5, p0, Llyiahf/vczjk/z3;->OooOOOo:I

    iput p6, p0, Llyiahf/vczjk/z3;->OooOOo0:I

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 8

    iget v0, p0, Llyiahf/vczjk/z3;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    move-object v5, p1

    check-cast v5, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget p1, p0, Llyiahf/vczjk/z3;->OooOOOo:I

    or-int/lit8 p1, p1, 0x1

    invoke-static {p1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v6

    iget-object v4, p0, Llyiahf/vczjk/z3;->OooOOOO:Llyiahf/vczjk/le3;

    iget v7, p0, Llyiahf/vczjk/z3;->OooOOo0:I

    iget-object v1, p0, Llyiahf/vczjk/z3;->OooOOO:Llyiahf/vczjk/kl5;

    iget-object p1, p0, Llyiahf/vczjk/z3;->OooOOo:Ljava/lang/Object;

    move-object v2, p1

    check-cast v2, Ljava/lang/String;

    iget-object v3, p0, Llyiahf/vczjk/z3;->OooOOoo:Llyiahf/vczjk/ze3;

    invoke-static/range {v1 .. v7}, Llyiahf/vczjk/e16;->OooO0oo(Llyiahf/vczjk/kl5;Ljava/lang/String;Llyiahf/vczjk/ze3;Llyiahf/vczjk/le3;Llyiahf/vczjk/rf1;II)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :pswitch_0
    move-object v4, p1

    check-cast v4, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget p1, p0, Llyiahf/vczjk/z3;->OooOOOo:I

    or-int/lit8 p1, p1, 0x1

    invoke-static {p1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v5

    iget-object p1, p0, Llyiahf/vczjk/z3;->OooOOoo:Llyiahf/vczjk/ze3;

    move-object v3, p1

    check-cast v3, Llyiahf/vczjk/a91;

    iget v6, p0, Llyiahf/vczjk/z3;->OooOOo0:I

    iget-object v0, p0, Llyiahf/vczjk/z3;->OooOOOO:Llyiahf/vczjk/le3;

    iget-object v1, p0, Llyiahf/vczjk/z3;->OooOOO:Llyiahf/vczjk/kl5;

    iget-object p1, p0, Llyiahf/vczjk/z3;->OooOOo:Ljava/lang/Object;

    move-object v2, p1

    check-cast v2, Llyiahf/vczjk/ab2;

    invoke-static/range {v0 .. v6}, Llyiahf/vczjk/j4;->OooO0Oo(Llyiahf/vczjk/le3;Llyiahf/vczjk/kl5;Llyiahf/vczjk/ab2;Llyiahf/vczjk/a91;Llyiahf/vczjk/rf1;II)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
