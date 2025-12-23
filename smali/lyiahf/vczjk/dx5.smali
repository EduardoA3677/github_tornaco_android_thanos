.class public final synthetic Llyiahf/vczjk/dx5;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field public final synthetic OooOOO:Z

.field public final synthetic OooOOO0:Llyiahf/vczjk/iw7;

.field public final synthetic OooOOOO:Llyiahf/vczjk/le3;

.field public final synthetic OooOOOo:Llyiahf/vczjk/a91;

.field public final synthetic OooOOo:Z

.field public final synthetic OooOOo0:Llyiahf/vczjk/kl5;

.field public final synthetic OooOOoo:Llyiahf/vczjk/a91;

.field public final synthetic OooOo0:I

.field public final synthetic OooOo00:Llyiahf/vczjk/yw5;


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/iw7;ZLlyiahf/vczjk/le3;Llyiahf/vczjk/a91;Llyiahf/vczjk/kl5;ZLlyiahf/vczjk/a91;Llyiahf/vczjk/yw5;I)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/dx5;->OooOOO0:Llyiahf/vczjk/iw7;

    iput-boolean p2, p0, Llyiahf/vczjk/dx5;->OooOOO:Z

    iput-object p3, p0, Llyiahf/vczjk/dx5;->OooOOOO:Llyiahf/vczjk/le3;

    iput-object p4, p0, Llyiahf/vczjk/dx5;->OooOOOo:Llyiahf/vczjk/a91;

    iput-object p5, p0, Llyiahf/vczjk/dx5;->OooOOo0:Llyiahf/vczjk/kl5;

    iput-boolean p6, p0, Llyiahf/vczjk/dx5;->OooOOo:Z

    iput-object p7, p0, Llyiahf/vczjk/dx5;->OooOOoo:Llyiahf/vczjk/a91;

    iput-object p8, p0, Llyiahf/vczjk/dx5;->OooOo00:Llyiahf/vczjk/yw5;

    iput p9, p0, Llyiahf/vczjk/dx5;->OooOo0:I

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 10

    move-object v8, p1

    check-cast v8, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget p1, p0, Llyiahf/vczjk/dx5;->OooOo0:I

    or-int/lit8 p1, p1, 0x1

    invoke-static {p1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v9

    iget-object v3, p0, Llyiahf/vczjk/dx5;->OooOOOo:Llyiahf/vczjk/a91;

    iget-object v6, p0, Llyiahf/vczjk/dx5;->OooOOoo:Llyiahf/vczjk/a91;

    iget-object v7, p0, Llyiahf/vczjk/dx5;->OooOo00:Llyiahf/vczjk/yw5;

    iget-object v0, p0, Llyiahf/vczjk/dx5;->OooOOO0:Llyiahf/vczjk/iw7;

    iget-boolean v1, p0, Llyiahf/vczjk/dx5;->OooOOO:Z

    iget-object v2, p0, Llyiahf/vczjk/dx5;->OooOOOO:Llyiahf/vczjk/le3;

    iget-object v4, p0, Llyiahf/vczjk/dx5;->OooOOo0:Llyiahf/vczjk/kl5;

    iget-boolean v5, p0, Llyiahf/vczjk/dx5;->OooOOo:Z

    invoke-static/range {v0 .. v9}, Llyiahf/vczjk/hx5;->OooO0O0(Llyiahf/vczjk/iw7;ZLlyiahf/vczjk/le3;Llyiahf/vczjk/a91;Llyiahf/vczjk/kl5;ZLlyiahf/vczjk/a91;Llyiahf/vczjk/yw5;Llyiahf/vczjk/rf1;I)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
