.class public final Llyiahf/vczjk/hl0;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field public final synthetic OooOOO:Z

.field public final synthetic OooOOO0:Z

.field public final synthetic OooOOOO:Llyiahf/vczjk/le3;

.field public final synthetic OooOOOo:Llyiahf/vczjk/qv3;


# direct methods
.method public constructor <init>(ZZLlyiahf/vczjk/le3;Llyiahf/vczjk/qv3;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-boolean p1, p0, Llyiahf/vczjk/hl0;->OooOOO0:Z

    iput-boolean p2, p0, Llyiahf/vczjk/hl0;->OooOOO:Z

    iput-object p3, p0, Llyiahf/vczjk/hl0;->OooOOOO:Llyiahf/vczjk/le3;

    iput-object p4, p0, Llyiahf/vczjk/hl0;->OooOOOo:Llyiahf/vczjk/qv3;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 12

    check-cast p1, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Number;

    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    move-result p2

    and-int/lit8 p2, p2, 0x3

    const/4 v0, 0x2

    if-ne p2, v0, :cond_1

    move-object p2, p1

    check-cast p2, Llyiahf/vczjk/zf1;

    invoke-virtual {p2}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v0

    if-nez v0, :cond_0

    goto :goto_0

    :cond_0
    invoke-virtual {p2}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_1

    :cond_1
    :goto_0
    iget-boolean p2, p0, Llyiahf/vczjk/hl0;->OooOOO0:Z

    if-nez p2, :cond_4

    sget-object v0, Llyiahf/vczjk/fz8;->OooO00o:Llyiahf/vczjk/fz8;

    move-object v10, p1

    check-cast v10, Llyiahf/vczjk/zf1;

    const p1, 0x4c5de2

    invoke-virtual {v10, p1}, Llyiahf/vczjk/zf1;->OoooO(I)V

    iget-object p1, p0, Llyiahf/vczjk/hl0;->OooOOOO:Llyiahf/vczjk/le3;

    invoke-virtual {v10, p1}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result p2

    invoke-virtual {v10}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v1

    if-nez p2, :cond_2

    sget-object p2, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-ne v1, p2, :cond_3

    :cond_2
    new-instance v1, Llyiahf/vczjk/hp;

    const/4 p2, 0x2

    invoke-direct {v1, p2, p1}, Llyiahf/vczjk/hp;-><init>(ILlyiahf/vczjk/le3;)V

    invoke-virtual {v10, v1}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_3
    move-object v2, v1

    check-cast v2, Llyiahf/vczjk/oe3;

    const/4 p1, 0x0

    invoke-virtual {v10, p1}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    new-instance p1, Llyiahf/vczjk/gl0;

    iget-boolean p2, p0, Llyiahf/vczjk/hl0;->OooOOO:Z

    iget-object v1, p0, Llyiahf/vczjk/hl0;->OooOOOo:Llyiahf/vczjk/qv3;

    const/4 v3, 0x0

    invoke-direct {p1, v3, v1, p2}, Llyiahf/vczjk/gl0;-><init>(ILjava/lang/Object;Z)V

    const p2, 0xfae5147

    invoke-static {p2, p1, v10}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v9

    const/4 v7, 0x0

    const/4 v8, 0x0

    iget-boolean v1, p0, Llyiahf/vczjk/hl0;->OooOOO:Z

    const/4 v3, 0x0

    const/4 v4, 0x0

    const/4 v5, 0x0

    const/4 v6, 0x0

    const/4 v11, 0x0

    invoke-virtual/range {v0 .. v11}, Llyiahf/vczjk/fz8;->OooO0OO(ZLlyiahf/vczjk/oe3;Llyiahf/vczjk/hl5;ZLlyiahf/vczjk/kz8;Llyiahf/vczjk/qk0;Llyiahf/vczjk/vk0;Llyiahf/vczjk/di6;Llyiahf/vczjk/a91;Llyiahf/vczjk/rf1;I)V

    :cond_4
    :goto_1
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
