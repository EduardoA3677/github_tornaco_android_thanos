.class public final synthetic Llyiahf/vczjk/b95;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/kl5;

.field public final synthetic OooOOO0:Ljava/lang/String;

.field public final synthetic OooOOOO:I

.field public final synthetic OooOOOo:I

.field public final synthetic OooOOo0:I


# direct methods
.method public synthetic constructor <init>(Ljava/lang/String;Llyiahf/vczjk/kl5;III)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/b95;->OooOOO0:Ljava/lang/String;

    iput-object p2, p0, Llyiahf/vczjk/b95;->OooOOO:Llyiahf/vczjk/kl5;

    iput p3, p0, Llyiahf/vczjk/b95;->OooOOOO:I

    iput p4, p0, Llyiahf/vczjk/b95;->OooOOOo:I

    iput p5, p0, Llyiahf/vczjk/b95;->OooOOo0:I

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 6

    move-object v3, p1

    check-cast v3, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget p1, p0, Llyiahf/vczjk/b95;->OooOOOo:I

    or-int/lit8 p1, p1, 0x1

    invoke-static {p1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v4

    iget-object v0, p0, Llyiahf/vczjk/b95;->OooOOO0:Ljava/lang/String;

    iget v2, p0, Llyiahf/vczjk/b95;->OooOOOO:I

    iget v5, p0, Llyiahf/vczjk/b95;->OooOOo0:I

    iget-object v1, p0, Llyiahf/vczjk/b95;->OooOOO:Llyiahf/vczjk/kl5;

    invoke-static/range {v0 .. v5}, Llyiahf/vczjk/rs;->OooO0OO(Ljava/lang/String;Llyiahf/vczjk/kl5;ILlyiahf/vczjk/rf1;II)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
