.class public final Llyiahf/vczjk/ru3;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $$changed:I

.field final synthetic $$default:I

.field final synthetic $alignment:Llyiahf/vczjk/o4;

.field final synthetic $alpha:F

.field final synthetic $colorFilter:Llyiahf/vczjk/p21;

.field final synthetic $contentDescription:Ljava/lang/String;

.field final synthetic $contentScale:Llyiahf/vczjk/en1;

.field final synthetic $modifier:Llyiahf/vczjk/kl5;

.field final synthetic $painter:Llyiahf/vczjk/un6;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/un6;Ljava/lang/String;Llyiahf/vczjk/kl5;Llyiahf/vczjk/o4;Llyiahf/vczjk/en1;FLlyiahf/vczjk/p21;II)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/ru3;->$painter:Llyiahf/vczjk/un6;

    iput-object p2, p0, Llyiahf/vczjk/ru3;->$contentDescription:Ljava/lang/String;

    iput-object p3, p0, Llyiahf/vczjk/ru3;->$modifier:Llyiahf/vczjk/kl5;

    iput-object p4, p0, Llyiahf/vczjk/ru3;->$alignment:Llyiahf/vczjk/o4;

    iput-object p5, p0, Llyiahf/vczjk/ru3;->$contentScale:Llyiahf/vczjk/en1;

    iput p6, p0, Llyiahf/vczjk/ru3;->$alpha:F

    iput-object p7, p0, Llyiahf/vczjk/ru3;->$colorFilter:Llyiahf/vczjk/p21;

    iput p8, p0, Llyiahf/vczjk/ru3;->$$changed:I

    iput p9, p0, Llyiahf/vczjk/ru3;->$$default:I

    const/4 p1, 0x2

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 10

    move-object v7, p1

    check-cast v7, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Number;

    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    iget-object v0, p0, Llyiahf/vczjk/ru3;->$painter:Llyiahf/vczjk/un6;

    iget-object v1, p0, Llyiahf/vczjk/ru3;->$contentDescription:Ljava/lang/String;

    iget-object v2, p0, Llyiahf/vczjk/ru3;->$modifier:Llyiahf/vczjk/kl5;

    iget-object v3, p0, Llyiahf/vczjk/ru3;->$alignment:Llyiahf/vczjk/o4;

    iget-object v4, p0, Llyiahf/vczjk/ru3;->$contentScale:Llyiahf/vczjk/en1;

    iget v5, p0, Llyiahf/vczjk/ru3;->$alpha:F

    iget-object v6, p0, Llyiahf/vczjk/ru3;->$colorFilter:Llyiahf/vczjk/p21;

    iget p1, p0, Llyiahf/vczjk/ru3;->$$changed:I

    or-int/lit8 p1, p1, 0x1

    invoke-static {p1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v8

    iget v9, p0, Llyiahf/vczjk/ru3;->$$default:I

    invoke-static/range {v0 .. v9}, Llyiahf/vczjk/c6a;->OooOOO(Llyiahf/vczjk/un6;Ljava/lang/String;Llyiahf/vczjk/kl5;Llyiahf/vczjk/o4;Llyiahf/vczjk/en1;FLlyiahf/vczjk/p21;Llyiahf/vczjk/rf1;II)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
