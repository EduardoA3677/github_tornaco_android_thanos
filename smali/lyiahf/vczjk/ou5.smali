.class public final synthetic Llyiahf/vczjk/ou5;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field public final synthetic OooOOO:Z

.field public final synthetic OooOOO0:I

.field public final synthetic OooOOOO:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/ir8;Z)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Llyiahf/vczjk/ou5;->OooOOO0:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/ou5;->OooOOOO:Ljava/lang/Object;

    iput-boolean p2, p0, Llyiahf/vczjk/ou5;->OooOOO:Z

    return-void
.end method

.method public synthetic constructor <init>(ZLlyiahf/vczjk/ze3;I)V
    .locals 0

    const/4 p3, 0x0

    iput p3, p0, Llyiahf/vczjk/ou5;->OooOOO0:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-boolean p1, p0, Llyiahf/vczjk/ou5;->OooOOO:Z

    iput-object p2, p0, Llyiahf/vczjk/ou5;->OooOOOO:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 13

    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    const/4 v1, 0x1

    iget-boolean v2, p0, Llyiahf/vczjk/ou5;->OooOOO:Z

    iget-object v3, p0, Llyiahf/vczjk/ou5;->OooOOOO:Ljava/lang/Object;

    iget v4, p0, Llyiahf/vczjk/ou5;->OooOOO0:I

    packed-switch v4, :pswitch_data_0

    move-object v5, p1

    check-cast v5, Llyiahf/vczjk/hg2;

    check-cast p2, Llyiahf/vczjk/p86;

    sget-object p1, Llyiahf/vczjk/pr8;->OooO00o:Llyiahf/vczjk/pr8;

    check-cast v3, Llyiahf/vczjk/ir8;

    invoke-virtual {v3, v2, v1}, Llyiahf/vczjk/ir8;->OooO00o(ZZ)J

    move-result-wide v6

    iget-wide v9, p2, Llyiahf/vczjk/p86;->OooO00o:J

    sget p1, Llyiahf/vczjk/pr8;->OooO0O0:F

    invoke-interface {v5, p1}, Llyiahf/vczjk/f62;->Ooooo00(F)F

    move-result p1

    const/high16 p2, 0x40000000    # 2.0f

    div-float v8, p1, p2

    const/16 v12, 0x78

    const/4 v11, 0x0

    invoke-static/range {v5 .. v12}, Llyiahf/vczjk/hg2;->OoooO0(Llyiahf/vczjk/hg2;JFJLlyiahf/vczjk/h79;I)V

    return-object v0

    :pswitch_0
    check-cast p1, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {v1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result p2

    check-cast v3, Llyiahf/vczjk/ze3;

    invoke-static {v2, v3, p1, p2}, Llyiahf/vczjk/qqa;->OooO0oo(ZLlyiahf/vczjk/ze3;Llyiahf/vczjk/rf1;I)V

    return-object v0

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
