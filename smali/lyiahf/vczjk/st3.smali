.class public final synthetic Llyiahf/vczjk/st3;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/kl5;

.field public final synthetic OooOOO0:Llyiahf/vczjk/le3;

.field public final synthetic OooOOOO:Z

.field public final synthetic OooOOOo:Llyiahf/vczjk/qj8;

.field public final synthetic OooOOo:I

.field public final synthetic OooOOo0:Llyiahf/vczjk/pt3;


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/le3;Llyiahf/vczjk/kl5;ZLlyiahf/vczjk/qj8;Llyiahf/vczjk/pt3;I)V
    .locals 1

    sget-object v0, Llyiahf/vczjk/ja1;->OooO00o:Llyiahf/vczjk/a91;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/st3;->OooOOO0:Llyiahf/vczjk/le3;

    iput-object p2, p0, Llyiahf/vczjk/st3;->OooOOO:Llyiahf/vczjk/kl5;

    iput-boolean p3, p0, Llyiahf/vczjk/st3;->OooOOOO:Z

    iput-object p4, p0, Llyiahf/vczjk/st3;->OooOOOo:Llyiahf/vczjk/qj8;

    iput-object p5, p0, Llyiahf/vczjk/st3;->OooOOo0:Llyiahf/vczjk/pt3;

    iput p6, p0, Llyiahf/vczjk/st3;->OooOOo:I

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    move-object v5, p1

    check-cast v5, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget p1, p0, Llyiahf/vczjk/st3;->OooOOo:I

    or-int/lit8 p1, p1, 0x1

    invoke-static {p1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v6

    sget-object p1, Llyiahf/vczjk/ja1;->OooO00o:Llyiahf/vczjk/a91;

    iget-object v0, p0, Llyiahf/vczjk/st3;->OooOOO0:Llyiahf/vczjk/le3;

    iget-object v1, p0, Llyiahf/vczjk/st3;->OooOOO:Llyiahf/vczjk/kl5;

    iget-boolean v2, p0, Llyiahf/vczjk/st3;->OooOOOO:Z

    iget-object v3, p0, Llyiahf/vczjk/st3;->OooOOOo:Llyiahf/vczjk/qj8;

    iget-object v4, p0, Llyiahf/vczjk/st3;->OooOOo0:Llyiahf/vczjk/pt3;

    invoke-static/range {v0 .. v6}, Llyiahf/vczjk/so8;->OooOO0o(Llyiahf/vczjk/le3;Llyiahf/vczjk/kl5;ZLlyiahf/vczjk/qj8;Llyiahf/vczjk/pt3;Llyiahf/vczjk/rf1;I)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
