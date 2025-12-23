.class public final Llyiahf/vczjk/bk0;
.super Llyiahf/vczjk/qg8;
.source "SourceFile"


# static fields
.field public static final OooOOO0:Llyiahf/vczjk/bk0;


# direct methods
.method static constructor <clinit>()V
    .locals 15

    new-instance v0, Llyiahf/vczjk/bk0;

    new-instance v1, Llyiahf/vczjk/iu2;

    invoke-direct {v1}, Llyiahf/vczjk/iu2;-><init>()V

    invoke-static {v1}, Llyiahf/vczjk/ik0;->OooO00o(Llyiahf/vczjk/iu2;)V

    sget-object v2, Llyiahf/vczjk/ik0;->OooO00o:Llyiahf/vczjk/ug3;

    const-string v3, "packageFqName"

    invoke-static {v2, v3}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    sget-object v3, Llyiahf/vczjk/ik0;->OooO0OO:Llyiahf/vczjk/ug3;

    const-string v4, "constructorAnnotation"

    invoke-static {v3, v4}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    sget-object v4, Llyiahf/vczjk/ik0;->OooO0O0:Llyiahf/vczjk/ug3;

    const-string v5, "classAnnotation"

    invoke-static {v4, v5}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    sget-object v5, Llyiahf/vczjk/ik0;->OooO0Oo:Llyiahf/vczjk/ug3;

    const-string v6, "functionAnnotation"

    invoke-static {v5, v6}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    sget-object v6, Llyiahf/vczjk/ik0;->OooO0o0:Llyiahf/vczjk/ug3;

    const-string v7, "propertyAnnotation"

    invoke-static {v6, v7}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    sget-object v7, Llyiahf/vczjk/ik0;->OooO0o:Llyiahf/vczjk/ug3;

    const-string v8, "propertyGetterAnnotation"

    invoke-static {v7, v8}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    sget-object v8, Llyiahf/vczjk/ik0;->OooO0oO:Llyiahf/vczjk/ug3;

    const-string v9, "propertySetterAnnotation"

    invoke-static {v8, v9}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    sget-object v9, Llyiahf/vczjk/ik0;->OooO:Llyiahf/vczjk/ug3;

    const-string v10, "enumEntryAnnotation"

    invoke-static {v9, v10}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    sget-object v10, Llyiahf/vczjk/ik0;->OooO0oo:Llyiahf/vczjk/ug3;

    const-string v11, "compileTimeValue"

    invoke-static {v10, v11}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    sget-object v11, Llyiahf/vczjk/ik0;->OooOO0:Llyiahf/vczjk/ug3;

    const-string v12, "parameterAnnotation"

    invoke-static {v11, v12}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    sget-object v12, Llyiahf/vczjk/ik0;->OooOO0O:Llyiahf/vczjk/ug3;

    const-string v13, "typeAnnotation"

    invoke-static {v12, v13}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    sget-object v13, Llyiahf/vczjk/ik0;->OooOO0o:Llyiahf/vczjk/ug3;

    const-string v14, "typeParameterAnnotation"

    invoke-static {v13, v14}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct/range {v0 .. v13}, Llyiahf/vczjk/qg8;-><init>(Llyiahf/vczjk/iu2;Llyiahf/vczjk/ug3;Llyiahf/vczjk/ug3;Llyiahf/vczjk/ug3;Llyiahf/vczjk/ug3;Llyiahf/vczjk/ug3;Llyiahf/vczjk/ug3;Llyiahf/vczjk/ug3;Llyiahf/vczjk/ug3;Llyiahf/vczjk/ug3;Llyiahf/vczjk/ug3;Llyiahf/vczjk/ug3;Llyiahf/vczjk/ug3;)V

    sput-object v0, Llyiahf/vczjk/bk0;->OooOOO0:Llyiahf/vczjk/bk0;

    return-void
.end method

.method public static OooO00o(Llyiahf/vczjk/hc3;)Ljava/lang/String;
    .locals 4

    const-string v0, "fqName"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v0, Ljava/lang/StringBuilder;

    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    iget-object p0, p0, Llyiahf/vczjk/hc3;->OooO00o:Llyiahf/vczjk/ic3;

    iget-object v1, p0, Llyiahf/vczjk/ic3;->OooO00o:Ljava/lang/String;

    const/16 v2, 0x2e

    const/16 v3, 0x2f

    invoke-static {v1, v2, v3}, Llyiahf/vczjk/g79;->OooOooo(Ljava/lang/String;CC)Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0, v3}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    invoke-virtual {p0}, Llyiahf/vczjk/ic3;->OooO0OO()Z

    move-result v1

    if-eqz v1, :cond_0

    const-string p0, "default-package"

    goto :goto_0

    :cond_0
    invoke-virtual {p0}, Llyiahf/vczjk/ic3;->OooO0o()Llyiahf/vczjk/qt5;

    move-result-object p0

    invoke-virtual {p0}, Llyiahf/vczjk/qt5;->OooO0O0()Ljava/lang/String;

    move-result-object p0

    const-string v1, "asString(...)"

    invoke-static {p0, v1}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    :goto_0
    const-string v1, ".kotlin_builtins"

    invoke-virtual {p0, v1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    move-result-object p0

    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p0

    return-object p0
.end method
