.class public final synthetic Llyiahf/vczjk/xk5;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field public final synthetic OooOOO:J

.field public final synthetic OooOOO0:Llyiahf/vczjk/le3;

.field public final synthetic OooOOOO:Llyiahf/vczjk/vk5;

.field public final synthetic OooOOOo:Llyiahf/vczjk/gi;

.field public final synthetic OooOOo:I

.field public final synthetic OooOOo0:Llyiahf/vczjk/a91;


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/le3;JLlyiahf/vczjk/vk5;Llyiahf/vczjk/gi;Llyiahf/vczjk/a91;I)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/xk5;->OooOOO0:Llyiahf/vczjk/le3;

    iput-wide p2, p0, Llyiahf/vczjk/xk5;->OooOOO:J

    iput-object p4, p0, Llyiahf/vczjk/xk5;->OooOOOO:Llyiahf/vczjk/vk5;

    iput-object p5, p0, Llyiahf/vczjk/xk5;->OooOOOo:Llyiahf/vczjk/gi;

    iput-object p6, p0, Llyiahf/vczjk/xk5;->OooOOo0:Llyiahf/vczjk/a91;

    iput p7, p0, Llyiahf/vczjk/xk5;->OooOOo:I

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 8

    move-object v6, p1

    check-cast v6, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget p1, p0, Llyiahf/vczjk/xk5;->OooOOo:I

    or-int/lit8 p1, p1, 0x1

    invoke-static {p1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v7

    iget-object v5, p0, Llyiahf/vczjk/xk5;->OooOOo0:Llyiahf/vczjk/a91;

    iget-object v0, p0, Llyiahf/vczjk/xk5;->OooOOO0:Llyiahf/vczjk/le3;

    iget-wide v1, p0, Llyiahf/vczjk/xk5;->OooOOO:J

    iget-object v3, p0, Llyiahf/vczjk/xk5;->OooOOOO:Llyiahf/vczjk/vk5;

    iget-object v4, p0, Llyiahf/vczjk/xk5;->OooOOOo:Llyiahf/vczjk/gi;

    invoke-static/range {v0 .. v7}, Llyiahf/vczjk/mc4;->OooO(Llyiahf/vczjk/le3;JLlyiahf/vczjk/vk5;Llyiahf/vczjk/gi;Llyiahf/vczjk/a91;Llyiahf/vczjk/rf1;I)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
