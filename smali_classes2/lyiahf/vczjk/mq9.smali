.class public final synthetic Llyiahf/vczjk/mq9;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field public final synthetic OooOOO:Z

.field public final synthetic OooOOO0:Z

.field public final synthetic OooOOOO:Llyiahf/vczjk/a91;

.field public final synthetic OooOOOo:I


# direct methods
.method public synthetic constructor <init>(ZZLlyiahf/vczjk/a91;I)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-boolean p1, p0, Llyiahf/vczjk/mq9;->OooOOO0:Z

    iput-boolean p2, p0, Llyiahf/vczjk/mq9;->OooOOO:Z

    iput-object p3, p0, Llyiahf/vczjk/mq9;->OooOOOO:Llyiahf/vczjk/a91;

    iput p4, p0, Llyiahf/vczjk/mq9;->OooOOOo:I

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    check-cast p1, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget p2, p0, Llyiahf/vczjk/mq9;->OooOOOo:I

    or-int/lit8 p2, p2, 0x1

    invoke-static {p2}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result p2

    iget-object v0, p0, Llyiahf/vczjk/mq9;->OooOOOO:Llyiahf/vczjk/a91;

    iget-boolean v1, p0, Llyiahf/vczjk/mq9;->OooOOO0:Z

    iget-boolean v2, p0, Llyiahf/vczjk/mq9;->OooOOO:Z

    invoke-static {v1, v2, v0, p1, p2}, Llyiahf/vczjk/nq9;->OooO00o(ZZLlyiahf/vczjk/a91;Llyiahf/vczjk/rf1;I)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
