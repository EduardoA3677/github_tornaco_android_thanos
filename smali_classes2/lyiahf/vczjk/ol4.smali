.class public final synthetic Llyiahf/vczjk/ol4;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field public final synthetic OooOOO:Z

.field public final synthetic OooOOO0:I

.field public final synthetic OooOOOO:I

.field public final synthetic OooOOOo:Ljava/lang/Object;

.field public final synthetic OooOOo:Llyiahf/vczjk/cf3;

.field public final synthetic OooOOo0:Llyiahf/vczjk/cf3;


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/ow5;Llyiahf/vczjk/oe3;Llyiahf/vczjk/oe3;ZI)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Llyiahf/vczjk/ol4;->OooOOO0:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/ol4;->OooOOOo:Ljava/lang/Object;

    iput-object p2, p0, Llyiahf/vczjk/ol4;->OooOOo0:Llyiahf/vczjk/cf3;

    iput-object p3, p0, Llyiahf/vczjk/ol4;->OooOOo:Llyiahf/vczjk/cf3;

    iput-boolean p4, p0, Llyiahf/vczjk/ol4;->OooOOO:Z

    iput p5, p0, Llyiahf/vczjk/ol4;->OooOOOO:I

    return-void
.end method

.method public synthetic constructor <init>(Llyiahf/vczjk/xu0;ZLlyiahf/vczjk/le3;Llyiahf/vczjk/le3;I)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Llyiahf/vczjk/ol4;->OooOOO0:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/ol4;->OooOOOo:Ljava/lang/Object;

    iput-boolean p2, p0, Llyiahf/vczjk/ol4;->OooOOO:Z

    iput-object p3, p0, Llyiahf/vczjk/ol4;->OooOOo0:Llyiahf/vczjk/cf3;

    iput-object p4, p0, Llyiahf/vczjk/ol4;->OooOOo:Llyiahf/vczjk/cf3;

    iput p5, p0, Llyiahf/vczjk/ol4;->OooOOOO:I

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    iget v0, p0, Llyiahf/vczjk/ol4;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    move-object v5, p1

    check-cast v5, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget p1, p0, Llyiahf/vczjk/ol4;->OooOOOO:I

    or-int/lit8 p1, p1, 0x1

    invoke-static {p1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v6

    iget-object p1, p0, Llyiahf/vczjk/ol4;->OooOOo:Llyiahf/vczjk/cf3;

    move-object v3, p1

    check-cast v3, Llyiahf/vczjk/oe3;

    iget-boolean v4, p0, Llyiahf/vczjk/ol4;->OooOOO:Z

    iget-object p1, p0, Llyiahf/vczjk/ol4;->OooOOOo:Ljava/lang/Object;

    move-object v1, p1

    check-cast v1, Llyiahf/vczjk/ow5;

    iget-object p1, p0, Llyiahf/vczjk/ol4;->OooOOo0:Llyiahf/vczjk/cf3;

    move-object v2, p1

    check-cast v2, Llyiahf/vczjk/oe3;

    invoke-static/range {v1 .. v6}, Llyiahf/vczjk/yi4;->OooOO0(Llyiahf/vczjk/ow5;Llyiahf/vczjk/oe3;Llyiahf/vczjk/oe3;ZLlyiahf/vczjk/rf1;I)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :pswitch_0
    move-object v4, p1

    check-cast v4, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    iget p1, p0, Llyiahf/vczjk/ol4;->OooOOOO:I

    or-int/lit8 p1, p1, 0x1

    invoke-static {p1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v5

    iget-object p1, p0, Llyiahf/vczjk/ol4;->OooOOOo:Ljava/lang/Object;

    move-object v0, p1

    check-cast v0, Llyiahf/vczjk/xu0;

    iget-boolean v1, p0, Llyiahf/vczjk/ol4;->OooOOO:Z

    iget-object p1, p0, Llyiahf/vczjk/ol4;->OooOOo0:Llyiahf/vczjk/cf3;

    move-object v2, p1

    check-cast v2, Llyiahf/vczjk/le3;

    iget-object p1, p0, Llyiahf/vczjk/ol4;->OooOOo:Llyiahf/vczjk/cf3;

    move-object v3, p1

    check-cast v3, Llyiahf/vczjk/le3;

    invoke-static/range {v0 .. v5}, Llyiahf/vczjk/m6a;->OooO0O0(Llyiahf/vczjk/xu0;ZLlyiahf/vczjk/le3;Llyiahf/vczjk/le3;Llyiahf/vczjk/rf1;I)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
